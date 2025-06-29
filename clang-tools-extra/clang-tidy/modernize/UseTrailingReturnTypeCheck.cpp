//===--- UseTrailingReturnTypeCheck.cpp - clang-tidy-----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "UseTrailingReturnTypeCheck.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Tooling/FixIt.h"
#include "llvm/ADT/StringExtras.h"

#include <cctype>
#include <optional>

namespace clang::tidy {

template <>
struct OptionEnumMapping<
    modernize::UseTrailingReturnTypeCheck::TransformLambda> {
  static llvm::ArrayRef<std::pair<
      modernize::UseTrailingReturnTypeCheck::TransformLambda, StringRef>>
  getEnumMapping() {
    static constexpr std::pair<
        modernize::UseTrailingReturnTypeCheck::TransformLambda, StringRef>
        Mapping[] = {
            {modernize::UseTrailingReturnTypeCheck::TransformLambda::All,
             "all"},
            {modernize::UseTrailingReturnTypeCheck::TransformLambda::
                 AllExceptAuto,
             "all_except_auto"},
            {modernize::UseTrailingReturnTypeCheck::TransformLambda::None,
             "none"}};
    return Mapping;
  }
};

} // namespace clang::tidy

using namespace clang::ast_matchers;

namespace clang::tidy::modernize {
namespace {
struct UnqualNameVisitor : public RecursiveASTVisitor<UnqualNameVisitor> {
public:
  UnqualNameVisitor(const FunctionDecl &F) : F(F) {}

  bool Collision = false;

  bool shouldWalkTypesOfTypeLocs() const { return false; }

  bool visitUnqualName(StringRef UnqualName) {
    // Check for collisions with function arguments.
    for (ParmVarDecl *Param : F.parameters())
      if (const IdentifierInfo *Ident = Param->getIdentifier())
        if (Ident->getName() == UnqualName) {
          Collision = true;
          return true;
        }
    return false;
  }

  bool TraverseTypeLoc(TypeLoc TL, bool Elaborated = false) {
    if (TL.isNull())
      return true;

    if (!Elaborated) {
      switch (TL.getTypeLocClass()) {
      case TypeLoc::Record:
        if (visitUnqualName(
                TL.getAs<RecordTypeLoc>().getTypePtr()->getDecl()->getName()))
          return false;
        break;
      case TypeLoc::Enum:
        if (visitUnqualName(
                TL.getAs<EnumTypeLoc>().getTypePtr()->getDecl()->getName()))
          return false;
        break;
      case TypeLoc::TemplateSpecialization:
        if (visitUnqualName(TL.getAs<TemplateSpecializationTypeLoc>()
                                .getTypePtr()
                                ->getTemplateName()
                                .getAsTemplateDecl()
                                ->getName()))
          return false;
        break;
      case TypeLoc::Typedef:
        if (visitUnqualName(
                TL.getAs<TypedefTypeLoc>().getTypePtr()->getDecl()->getName()))
          return false;
        break;
      case TypeLoc::Using:
        if (visitUnqualName(TL.getAs<UsingTypeLoc>()
                                .getTypePtr()
                                ->getFoundDecl()
                                ->getName()))
          return false;
        break;
      default:
        break;
      }
    }

    return RecursiveASTVisitor<UnqualNameVisitor>::TraverseTypeLoc(TL);
  }

  // Replace the base method in order to call our own
  // TraverseTypeLoc().
  bool TraverseQualifiedTypeLoc(QualifiedTypeLoc TL) {
    return TraverseTypeLoc(TL.getUnqualifiedLoc());
  }

  // Replace the base version to inform TraverseTypeLoc that the type is
  // elaborated.
  bool TraverseElaboratedTypeLoc(ElaboratedTypeLoc TL) {
    if (TL.getQualifierLoc() &&
        !TraverseNestedNameSpecifierLoc(TL.getQualifierLoc()))
      return false;
    const auto *T = TL.getTypePtr();
    return TraverseTypeLoc(TL.getNamedTypeLoc(),
                           T->getKeyword() != ElaboratedTypeKeyword::None ||
                               T->getQualifier());
  }

  bool VisitDeclRefExpr(DeclRefExpr *S) {
    DeclarationName Name = S->getNameInfo().getName();
    return S->getQualifierLoc() || Name.isEmpty() || !Name.isIdentifier() ||
           !visitUnqualName(Name.getAsIdentifierInfo()->getName());
  }

private:
  const FunctionDecl &F;
};

AST_MATCHER(LambdaExpr, hasExplicitResultType) {
  return Node.hasExplicitResultType();
}

} // namespace

constexpr llvm::StringLiteral ErrorMessageOnFunction =
    "use a trailing return type for this function";
constexpr llvm::StringLiteral ErrorMessageOnLambda =
    "use a trailing return type for this lambda";

static SourceLocation expandIfMacroId(SourceLocation Loc,
                                      const SourceManager &SM) {
  if (Loc.isMacroID())
    Loc = expandIfMacroId(SM.getImmediateExpansionRange(Loc).getBegin(), SM);
  assert(!Loc.isMacroID() &&
         "SourceLocation must not be a macro ID after recursive expansion");
  return Loc;
}

static SourceLocation findTrailingReturnTypeSourceLocation(
    const FunctionDecl &F, const FunctionTypeLoc &FTL, const ASTContext &Ctx,
    const SourceManager &SM, const LangOptions &LangOpts) {
  // We start with the location of the closing parenthesis.
  SourceRange ExceptionSpecRange = F.getExceptionSpecSourceRange();
  if (ExceptionSpecRange.isValid())
    return Lexer::getLocForEndOfToken(ExceptionSpecRange.getEnd(), 0, SM,
                                      LangOpts);

  // If the function argument list ends inside of a macro, it is dangerous to
  // start lexing from here - bail out.
  SourceLocation ClosingParen = FTL.getRParenLoc();
  if (ClosingParen.isMacroID())
    return {};

  SourceLocation Result =
      Lexer::getLocForEndOfToken(ClosingParen, 0, SM, LangOpts);

  // Skip subsequent CV and ref qualifiers.
  std::pair<FileID, unsigned> Loc = SM.getDecomposedLoc(Result);
  StringRef File = SM.getBufferData(Loc.first);
  const char *TokenBegin = File.data() + Loc.second;
  Lexer Lexer(SM.getLocForStartOfFile(Loc.first), LangOpts, File.begin(),
              TokenBegin, File.end());
  Token T;
  while (!Lexer.LexFromRawLexer(T)) {
    if (T.is(tok::raw_identifier)) {
      IdentifierInfo &Info = Ctx.Idents.get(
          StringRef(SM.getCharacterData(T.getLocation()), T.getLength()));
      T.setIdentifierInfo(&Info);
      T.setKind(Info.getTokenID());
    }

    if (T.isOneOf(tok::amp, tok::ampamp, tok::kw_const, tok::kw_volatile,
                  tok::kw_restrict)) {
      Result = T.getEndLoc();
      continue;
    }
    break;
  }
  return Result;
}

static bool isCvr(Token T) {
  return T.isOneOf(tok::kw_const, tok::kw_volatile, tok::kw_restrict);
}

static bool isSpecifier(Token T) {
  return T.isOneOf(tok::kw_constexpr, tok::kw_inline, tok::kw_extern,
                   tok::kw_static, tok::kw_friend, tok::kw_virtual);
}

static std::optional<ClassifiedToken>
classifyToken(const FunctionDecl &F, Preprocessor &PP, Token Tok) {
  ClassifiedToken CT;
  CT.T = Tok;
  CT.IsQualifier = true;
  CT.IsSpecifier = true;
  bool ContainsQualifiers = false;
  bool ContainsSpecifiers = false;
  bool ContainsSomethingElse = false;

  Token End;
  End.startToken();
  End.setKind(tok::eof);
  SmallVector<Token, 2> Stream{Tok, End};

  // FIXME: do not report these token to Preprocessor.TokenWatcher.
  PP.EnterTokenStream(Stream, false, /*IsReinject=*/false);
  while (true) {
    Token T;
    PP.Lex(T);
    if (T.is(tok::eof))
      break;

    bool Qual = isCvr(T);
    bool Spec = isSpecifier(T);
    CT.IsQualifier &= Qual;
    CT.IsSpecifier &= Spec;
    ContainsQualifiers |= Qual;
    ContainsSpecifiers |= Spec;
    ContainsSomethingElse |= !Qual && !Spec;
  }

  // If the Token/Macro contains more than one type of tokens, we would need
  // to split the macro in order to move parts to the trailing return type.
  if (ContainsQualifiers + ContainsSpecifiers + ContainsSomethingElse > 1)
    return std::nullopt;

  return CT;
}

static std::optional<SmallVector<ClassifiedToken, 8>>
classifyTokensBeforeFunctionName(const FunctionDecl &F, const ASTContext &Ctx,
                                 const SourceManager &SM,
                                 const LangOptions &LangOpts,
                                 Preprocessor *PP) {
  SourceLocation BeginF = expandIfMacroId(F.getBeginLoc(), SM);
  SourceLocation BeginNameF = expandIfMacroId(F.getLocation(), SM);

  // Create tokens for everything before the name of the function.
  std::pair<FileID, unsigned> Loc = SM.getDecomposedLoc(BeginF);
  StringRef File = SM.getBufferData(Loc.first);
  const char *TokenBegin = File.data() + Loc.second;
  Lexer Lexer(SM.getLocForStartOfFile(Loc.first), LangOpts, File.begin(),
              TokenBegin, File.end());
  Token T;
  SmallVector<ClassifiedToken, 8> ClassifiedTokens;
  while (!Lexer.LexFromRawLexer(T) &&
         SM.isBeforeInTranslationUnit(T.getLocation(), BeginNameF)) {
    if (T.is(tok::raw_identifier)) {
      IdentifierInfo &Info = Ctx.Idents.get(
          StringRef(SM.getCharacterData(T.getLocation()), T.getLength()));

      if (Info.hasMacroDefinition()) {
        const MacroInfo *MI = PP->getMacroInfo(&Info);
        if (!MI || MI->isFunctionLike()) {
          // Cannot handle function style macros.
          return std::nullopt;
        }
      }

      T.setIdentifierInfo(&Info);
      T.setKind(Info.getTokenID());
    }

    if (std::optional<ClassifiedToken> CT = classifyToken(F, *PP, T))
      ClassifiedTokens.push_back(*CT);
    else
      return std::nullopt;
  }

  return ClassifiedTokens;
}

static bool hasAnyNestedLocalQualifiers(QualType Type) {
  bool Result = Type.hasLocalQualifiers();
  if (Type->isPointerType())
    Result = Result || hasAnyNestedLocalQualifiers(
                           Type->castAs<PointerType>()->getPointeeType());
  if (Type->isReferenceType())
    Result = Result || hasAnyNestedLocalQualifiers(
                           Type->castAs<ReferenceType>()->getPointeeType());
  return Result;
}

static SourceRange
findReturnTypeAndCVSourceRange(const FunctionDecl &F, const TypeLoc &ReturnLoc,
                               const ASTContext &Ctx, const SourceManager &SM,
                               const LangOptions &LangOpts, Preprocessor *PP) {

  // We start with the range of the return type and expand to neighboring
  // qualifiers (const, volatile and restrict).
  SourceRange ReturnTypeRange = F.getReturnTypeSourceRange();
  if (ReturnTypeRange.isInvalid()) {
    // Happens if e.g. clang cannot resolve all includes and the return type is
    // unknown.
    return {};
  }

  // If the return type has no local qualifiers, it's source range is accurate.
  if (!hasAnyNestedLocalQualifiers(F.getReturnType()))
    return ReturnTypeRange;

  // Include qualifiers to the left and right of the return type.
  std::optional<SmallVector<ClassifiedToken, 8>> MaybeTokens =
      classifyTokensBeforeFunctionName(F, Ctx, SM, LangOpts, PP);
  if (!MaybeTokens)
    return {};
  const SmallVector<ClassifiedToken, 8> &Tokens = *MaybeTokens;

  ReturnTypeRange.setBegin(expandIfMacroId(ReturnTypeRange.getBegin(), SM));
  ReturnTypeRange.setEnd(expandIfMacroId(ReturnTypeRange.getEnd(), SM));

  bool ExtendedLeft = false;
  for (size_t I = 0; I < Tokens.size(); I++) {
    // If we found the beginning of the return type, include left qualifiers.
    if (!SM.isBeforeInTranslationUnit(Tokens[I].T.getLocation(),
                                      ReturnTypeRange.getBegin()) &&
        !ExtendedLeft) {
      assert(I <= size_t(std::numeric_limits<int>::max()) &&
             "Integer overflow detected");
      for (int J = static_cast<int>(I) - 1; J >= 0 && Tokens[J].IsQualifier;
           J--)
        ReturnTypeRange.setBegin(Tokens[J].T.getLocation());
      ExtendedLeft = true;
    }
    // If we found the end of the return type, include right qualifiers.
    if (SM.isBeforeInTranslationUnit(ReturnTypeRange.getEnd(),
                                     Tokens[I].T.getLocation())) {
      for (size_t J = I; J < Tokens.size() && Tokens[J].IsQualifier; J++)
        ReturnTypeRange.setEnd(Tokens[J].T.getLocation());
      break;
    }
  }

  assert(!ReturnTypeRange.getBegin().isMacroID() &&
         "Return type source range begin must not be a macro");
  assert(!ReturnTypeRange.getEnd().isMacroID() &&
         "Return type source range end must not be a macro");
  return ReturnTypeRange;
}

static SourceLocation findLambdaTrailingReturnInsertLoc(
    const CXXMethodDecl *Method, const SourceManager &SM,
    const LangOptions &LangOpts, const ASTContext &Ctx) {
  // 'requires' keyword is present in lambda declaration
  if (Method->getTrailingRequiresClause()) {
    SourceLocation ParamEndLoc;
    if (Method->param_empty())
      ParamEndLoc = Method->getBeginLoc();
    else
      ParamEndLoc = Method->getParametersSourceRange().getEnd();

    std::pair<FileID, unsigned> ParamEndLocInfo =
        SM.getDecomposedLoc(ParamEndLoc);
    StringRef Buffer = SM.getBufferData(ParamEndLocInfo.first);

    Lexer Lexer(SM.getLocForStartOfFile(ParamEndLocInfo.first), LangOpts,
                Buffer.begin(), Buffer.data() + ParamEndLocInfo.second,
                Buffer.end());

    Token Token;
    while (!Lexer.LexFromRawLexer(Token)) {
      if (Token.is(tok::raw_identifier)) {
        IdentifierInfo &Info = Ctx.Idents.get(StringRef(
            SM.getCharacterData(Token.getLocation()), Token.getLength()));
        Token.setIdentifierInfo(&Info);
        Token.setKind(Info.getTokenID());
      }

      if (Token.is(tok::kw_requires))
        return Token.getLocation().getLocWithOffset(-1);
    }

    return {};
  }

  // If no requires clause, insert before the body
  if (const Stmt *Body = Method->getBody())
    return Body->getBeginLoc().getLocWithOffset(-1);

  return {};
}

static void keepSpecifiers(std::string &ReturnType, std::string &Auto,
                           SourceRange ReturnTypeCVRange, const FunctionDecl &F,
                           const FriendDecl *Fr, const ASTContext &Ctx,
                           const SourceManager &SM, const LangOptions &LangOpts,
                           Preprocessor *PP) {
  // Check if there are specifiers inside the return type. E.g. unsigned
  // inline int.
  const auto *M = dyn_cast<CXXMethodDecl>(&F);
  if (!F.isConstexpr() && !F.isInlineSpecified() &&
      F.getStorageClass() != SC_Extern && F.getStorageClass() != SC_Static &&
      !Fr && !(M && M->isVirtualAsWritten()))
    return;

  // Tokenize return type. If it contains macros which contain a mix of
  // qualifiers, specifiers and types, give up.
  std::optional<SmallVector<ClassifiedToken, 8>> MaybeTokens =
      classifyTokensBeforeFunctionName(F, Ctx, SM, LangOpts, PP);
  if (!MaybeTokens)
    return;

  // Find specifiers, remove them from the return type, add them to 'auto'.
  unsigned int ReturnTypeBeginOffset =
      SM.getDecomposedLoc(ReturnTypeCVRange.getBegin()).second;
  size_t InitialAutoLength = Auto.size();
  unsigned int DeletedChars = 0;
  for (ClassifiedToken CT : *MaybeTokens) {
    if (SM.isBeforeInTranslationUnit(CT.T.getLocation(),
                                     ReturnTypeCVRange.getBegin()) ||
        SM.isBeforeInTranslationUnit(ReturnTypeCVRange.getEnd(),
                                     CT.T.getLocation()))
      continue;
    if (!CT.IsSpecifier)
      continue;

    // Add the token to 'auto' and remove it from the return type, including
    // any whitespace following the token.
    unsigned int TOffset = SM.getDecomposedLoc(CT.T.getLocation()).second;
    assert(TOffset >= ReturnTypeBeginOffset &&
           "Token location must be after the beginning of the return type");
    unsigned int TOffsetInRT = TOffset - ReturnTypeBeginOffset - DeletedChars;
    unsigned int TLengthWithWS = CT.T.getLength();
    while (TOffsetInRT + TLengthWithWS < ReturnType.size() &&
           llvm::isSpace(ReturnType[TOffsetInRT + TLengthWithWS]))
      TLengthWithWS++;
    std::string Specifier = ReturnType.substr(TOffsetInRT, TLengthWithWS);
    if (!llvm::isSpace(Specifier.back()))
      Specifier.push_back(' ');
    Auto.insert(Auto.size() - InitialAutoLength, Specifier);
    ReturnType.erase(TOffsetInRT, TLengthWithWS);
    DeletedChars += TLengthWithWS;
  }
}

UseTrailingReturnTypeCheck::UseTrailingReturnTypeCheck(
    StringRef Name, ClangTidyContext *Context)
    : ClangTidyCheck(Name, Context),
      TransformFunctions(Options.get("TransformFunctions", true)),
      TransformLambdas(Options.get("TransformLambdas", TransformLambda::All)) {

  if (TransformFunctions == false && TransformLambdas == TransformLambda::None)
    this->configurationDiag(
        "The check 'modernize-use-trailing-return-type' will not perform any "
        "analysis because 'TransformFunctions' and 'TransformLambdas' are "
        "disabled.");
}

void UseTrailingReturnTypeCheck::storeOptions(
    ClangTidyOptions::OptionMap &Opts) {
  Options.store(Opts, "TransformFunctions", TransformFunctions);
  Options.store(Opts, "TransformLambdas", TransformLambdas);
}

void UseTrailingReturnTypeCheck::registerMatchers(MatchFinder *Finder) {
  auto F =
      functionDecl(
          unless(anyOf(
              hasTrailingReturn(), returns(voidType()), cxxConversionDecl(),
              cxxMethodDecl(
                  anyOf(isImplicit(),
                        hasParent(cxxRecordDecl(hasParent(lambdaExpr()))))))))
          .bind("Func");

  if (TransformFunctions) {
    Finder->addMatcher(F, this);
    Finder->addMatcher(friendDecl(hasDescendant(F)).bind("Friend"), this);
  }

  if (TransformLambdas != TransformLambda::None)
    Finder->addMatcher(
        lambdaExpr(unless(hasExplicitResultType())).bind("Lambda"), this);
}

void UseTrailingReturnTypeCheck::registerPPCallbacks(
    const SourceManager &SM, Preprocessor *PP, Preprocessor *ModuleExpanderPP) {
  this->PP = PP;
}

void UseTrailingReturnTypeCheck::check(const MatchFinder::MatchResult &Result) {
  assert(PP && "Expected registerPPCallbacks() to have been called before so "
               "preprocessor is available");

  if (const auto *Lambda = Result.Nodes.getNodeAs<LambdaExpr>("Lambda")) {
    diagOnLambda(Lambda, Result);
    return;
  }

  const auto *Fr = Result.Nodes.getNodeAs<FriendDecl>("Friend");
  const auto *F = Result.Nodes.getNodeAs<FunctionDecl>("Func");
  assert(F && "Matcher is expected to find only FunctionDecls");

  // Three-way comparison operator<=> is syntactic sugar and generates implicit
  // nodes for all other operators.
  if (F->getLocation().isInvalid() || F->isImplicit())
    return;

  // Skip functions which return 'auto' and defaulted operators.
  const auto *AT = F->getDeclaredReturnType()->getAs<AutoType>();
  if (AT != nullptr &&
      ((!AT->isConstrained() && AT->getKeyword() == AutoTypeKeyword::Auto &&
        !hasAnyNestedLocalQualifiers(F->getDeclaredReturnType())) ||
       F->isDefaulted()))
    return;

  // TODO: implement those
  if (F->getDeclaredReturnType()->isFunctionPointerType() ||
      F->getDeclaredReturnType()->isMemberFunctionPointerType() ||
      F->getDeclaredReturnType()->isMemberPointerType()) {
    diag(F->getLocation(), ErrorMessageOnFunction);
    return;
  }

  const ASTContext &Ctx = *Result.Context;
  const SourceManager &SM = *Result.SourceManager;
  const LangOptions &LangOpts = getLangOpts();

  const TypeSourceInfo *TSI = F->getTypeSourceInfo();
  if (!TSI)
    return;

  auto FTL = TSI->getTypeLoc().IgnoreParens().getAs<FunctionTypeLoc>();
  if (!FTL) {
    // FIXME: This may happen if we have __attribute__((...)) on the function.
    // We abort for now. Remove this when the function type location gets
    // available in clang.
    diag(F->getLocation(), ErrorMessageOnFunction);
    return;
  }

  SourceLocation InsertionLoc =
      findTrailingReturnTypeSourceLocation(*F, FTL, Ctx, SM, LangOpts);
  if (InsertionLoc.isInvalid()) {
    diag(F->getLocation(), ErrorMessageOnFunction);
    return;
  }

  // Using the declared return type via F->getDeclaredReturnType().getAsString()
  // discards user formatting and order of const, volatile, type, whitespace,
  // space before & ... .
  SourceRange ReturnTypeCVRange = findReturnTypeAndCVSourceRange(
      *F, FTL.getReturnLoc(), Ctx, SM, LangOpts, PP);
  if (ReturnTypeCVRange.isInvalid()) {
    diag(F->getLocation(), ErrorMessageOnFunction);
    return;
  }

  // Check if unqualified names in the return type conflict with other entities
  // after the rewrite.
  // FIXME: this could be done better, by performing a lookup of all
  // unqualified names in the return type in the scope of the function. If the
  // lookup finds a different entity than the original entity identified by the
  // name, then we can either not perform a rewrite or explicitly qualify the
  // entity. Such entities could be function parameter names, (inherited) class
  // members, template parameters, etc.
  UnqualNameVisitor UNV{*F};
  UNV.TraverseTypeLoc(FTL.getReturnLoc());
  if (UNV.Collision) {
    diag(F->getLocation(), ErrorMessageOnFunction);
    return;
  }

  SourceLocation ReturnTypeEnd =
      Lexer::getLocForEndOfToken(ReturnTypeCVRange.getEnd(), 0, SM, LangOpts);
  StringRef CharAfterReturnType = Lexer::getSourceText(
      CharSourceRange::getCharRange(ReturnTypeEnd,
                                    ReturnTypeEnd.getLocWithOffset(1)),
      SM, LangOpts);
  bool NeedSpaceAfterAuto =
      CharAfterReturnType.empty() || !llvm::isSpace(CharAfterReturnType[0]);

  std::string Auto = NeedSpaceAfterAuto ? "auto " : "auto";
  std::string ReturnType =
      std::string(tooling::fixit::getText(ReturnTypeCVRange, Ctx));
  keepSpecifiers(ReturnType, Auto, ReturnTypeCVRange, *F, Fr, Ctx, SM, LangOpts,
                 PP);

  diag(F->getLocation(), ErrorMessageOnFunction)
      << FixItHint::CreateReplacement(ReturnTypeCVRange, Auto)
      << FixItHint::CreateInsertion(InsertionLoc, " -> " + ReturnType);
}

void UseTrailingReturnTypeCheck::diagOnLambda(
    const LambdaExpr *Lambda,
    const ast_matchers::MatchFinder::MatchResult &Result) {

  const CXXMethodDecl *Method = Lambda->getCallOperator();
  if (!Method || Lambda->hasExplicitResultType())
    return;

  const ASTContext *Ctx = Result.Context;
  const QualType ReturnType = Method->getReturnType();

  // We can't write 'auto' in C++11 mode, try to write generic msg and bail out.
  if (ReturnType->isDependentType() &&
      Ctx->getLangOpts().LangStd == LangStandard::lang_cxx11) {
    if (TransformLambdas == TransformLambda::All)
      diag(Lambda->getBeginLoc(), ErrorMessageOnLambda);
    return;
  }

  if (ReturnType->isUndeducedAutoType() &&
      TransformLambdas == TransformLambda::AllExceptAuto)
    return;

  const SourceLocation TrailingReturnInsertLoc =
      findLambdaTrailingReturnInsertLoc(Method, *Result.SourceManager,
                                        getLangOpts(), *Result.Context);

  if (TrailingReturnInsertLoc.isValid())
    diag(Lambda->getBeginLoc(), "use a trailing return type for this lambda")
        << FixItHint::CreateInsertion(
               TrailingReturnInsertLoc,
               " -> " +
                   ReturnType.getAsString(Result.Context->getPrintingPolicy()));
  else
    diag(Lambda->getBeginLoc(), ErrorMessageOnLambda);
}

} // namespace clang::tidy::modernize
