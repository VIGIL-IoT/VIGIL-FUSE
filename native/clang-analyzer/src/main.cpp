// Compiler observations only. Security interpretation belongs to Python.
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Basic/Version.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Lex/Lexer.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

namespace fs = std::filesystem;
using namespace clang;
constexpr size_t MaxBytes = 1024 * 1024, MaxObservations = 1024, MaxFiles = 32;

static std::string readBounded(const fs::path &path) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) throw std::runtime_error("Input unavailable");
  std::string text(MaxBytes + 1, '\0');
  stream.read(text.data(), text.size());
  text.resize(static_cast<size_t>(stream.gcount()));
  if (text.size() > MaxBytes) throw std::runtime_error("Input byte limit exceeded");
  return text;
}

static std::string relativeInsideRoot(const fs::path &path, const fs::path &root) {
  auto name = fs::relative(fs::canonical(path), root).generic_string();
  if (name.empty() || name.size() > 1024 || name == ".." || name.rfind("../", 0) == 0)
    throw std::runtime_error("Input escapes selected root");
  return name;
}

struct Evidence {
  fs::path root;
  llvm::json::Array observations, units;
  bool partial = false;
  unsigned diagnostics = 0;
};

class Diagnostics : public DiagnosticConsumer {
  Evidence &evidence;
public:
  bool errors = false;
  explicit Diagnostics(Evidence &e) : evidence(e) {}
  void HandleDiagnostic(DiagnosticsEngine::Level level, const Diagnostic &) override {
    if (level >= DiagnosticsEngine::Warning) {
      if (evidence.diagnostics < 64) ++evidence.diagnostics;
      evidence.partial = true;
    }
    if (level >= DiagnosticsEngine::Error) errors = true;
  }
};

class Visitor : public RecursiveASTVisitor<Visitor> {
  ASTContext &context;
  Evidence &evidence;
  std::string enclosing;

  void observe(std::string kind, std::string name, SourceLocation location,
               bool definition, llvm::json::Array arguments = {}) {
    auto &sm = context.getSourceManager();
    auto expanded = sm.getExpansionLoc(location);
    if (!expanded.isValid() || !sm.isWrittenInMainFile(expanded)) return;
    if (evidence.observations.size() >= MaxObservations) { evidence.partial = true; return; }
    if (name.size() > 256 || enclosing.size() > 256) evidence.partial = true;
    auto spelling = sm.getSpellingLoc(location);
    std::string file, spellingFile;
    try {
      file = relativeInsideRoot(sm.getFilename(expanded).str(), evidence.root);
      spellingFile = relativeInsideRoot(sm.getFilename(spelling).str(), evidence.root);
    } catch (...) { evidence.partial = true; return; }
    evidence.observations.emplace_back(llvm::json::Object{
      {"kind", kind}, {"name", name.substr(0, 256)}, {"file", file},
      {"line", sm.getSpellingLineNumber(expanded)}, {"column", sm.getSpellingColumnNumber(expanded)},
      {"spelling_file", spellingFile}, {"spelling_line", sm.getSpellingLineNumber(spelling)},
      {"function", enclosing.substr(0, 256)}, {"definition", definition},
      {"arguments", std::move(arguments)}});
  }

public:
  Visitor(ASTContext &c, Evidence &e) : context(c), evidence(e) {}
  bool TraverseDecl(Decl *declaration) {
    auto previous = enclosing;
    if (auto *function = dyn_cast_or_null<FunctionDecl>(declaration))
      enclosing = function->getQualifiedNameAsString();
    bool result = RecursiveASTVisitor<Visitor>::TraverseDecl(declaration);
    enclosing = previous;
    return result;
  }
  bool VisitFunctionDecl(FunctionDecl *declaration) {
    observe("function", declaration->getQualifiedNameAsString(), declaration->getLocation(),
            declaration->isThisDeclarationADefinition());
    return true;
  }
  bool VisitCallExpr(CallExpr *call) {
    llvm::json::Array arguments;
    if (call->getNumArgs() > 32) { evidence.partial = true; return true; }
    for (const auto *argument : call->arguments()) {
      auto text = Lexer::getSourceText(CharSourceRange::getTokenRange(argument->getSourceRange()),
                                      context.getSourceManager(), context.getLangOpts()).str();
      auto *expression = argument->IgnoreParenImpCasts();
      if (text.size() > 256) evidence.partial = true;
      arguments.emplace_back(llvm::json::Object{
        {"expression", text.substr(0, 256)},
        {"literal", isa<StringLiteral>(expression) || isa<IntegerLiteral>(expression)},
        {"integer_constant", argument->isIntegerConstantExpr(context)}});
    }
    auto *callee = call->getDirectCallee();
    observe("call", callee ? callee->getQualifiedNameAsString() : "<unresolved>",
            call->getExprLoc(), false, std::move(arguments));
    return true;
  }
};

class Consumer : public ASTConsumer {
  Evidence &evidence;
public:
  explicit Consumer(Evidence &e) : evidence(e) {}
  void HandleTranslationUnit(ASTContext &context) override {
    Visitor visitor(context, evidence);
    visitor.TraverseDecl(context.getTranslationUnitDecl());
  }
};

class Action : public ASTFrontendAction {
  Evidence &evidence;
public:
  explicit Action(Evidence &e) : evidence(e) {}
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &, llvm::StringRef) override {
    return std::make_unique<Consumer>(evidence);
  }
};

class Factory : public tooling::FrontendActionFactory {
  Evidence &evidence;
public:
  explicit Factory(Evidence &e) : evidence(e) {}
  std::unique_ptr<FrontendAction> create() override { return std::make_unique<Action>(evidence); }
};

int main(int argc, char **argv) {
  if (argc == 2 && std::string(argv[1]) == "--version") {
    std::cout << llvm::formatv("{0}\n", llvm::json::Value(llvm::json::Object{
      {"tool", "fuse-clang-analyzer"}, {"schema_version", "1.0"},
      {"clang_version", CLANG_VERSION_STRING}, {"compile_commands", true}})).str();
    return 0;
  }
  if (argc != 3) { std::cerr << "Usage: fuse-clang-analyzer ROOT COMPILE_COMMANDS\n"; return 2; }
  std::thread([] { std::this_thread::sleep_for(std::chrono::seconds(60)); std::_Exit(124); }).detach();
  try {
    Evidence evidence;
    if (std::getenv("CCC_OVERRIDE_OPTIONS"))
      throw std::runtime_error("Compiler environment overrides are unsupported");
    evidence.root = fs::canonical(argv[1]);
    auto databasePath = fs::canonical(argv[2]);
    relativeInsideRoot(databasePath, evidence.root);
    auto parsed = llvm::json::parse(readBounded(databasePath));
    if (!parsed) { llvm::consumeError(parsed.takeError()); throw std::runtime_error("Invalid database JSON"); }
    auto *entries = parsed->getAsArray();
    if (!entries || entries->empty() || entries->size() > MaxFiles)
      throw std::runtime_error("Database must contain 1..32 compilation entries");
    for (const auto &entry : *entries) {
      Evidence unitEvidence;
      unitEvidence.root = evidence.root;
      auto *object = entry.getAsObject();
      if (!object) throw std::runtime_error("Invalid compilation entry");
      auto directory = object->getString("directory"), file = object->getString("file");
      auto *arguments = object->getArray("arguments");
      if (!directory || !file || !arguments || arguments->empty() || arguments->size() > 128)
        throw std::runtime_error("Explicit bounded arguments array required");
      auto compiler = (*arguments)[0].getAsString();
      if (!compiler || compiler->empty() || compiler->size() > 1024)
        throw std::runtime_error("Invalid compiler identifier");
      auto working = fs::canonical(evidence.root / directory->str());
      relativeInsideRoot(working, evidence.root);
      auto source = fs::canonical(working / file->str());
      auto name = relativeInsideRoot(source, evidence.root);
      readBounded(source);
      std::vector<std::string> flags;
      for (size_t index = 1; index < arguments->size(); ++index) {
        auto value = (*arguments)[index].getAsString();
        if (!value || value->size() > 1024) throw std::runtime_error("Invalid compiler argument");
        auto flag = value->str();
        if (flag == "-c" || flag == file->str() || flag == source.string()) continue;
        if (flag == "-o") { if (++index >= arguments->size()) throw std::runtime_error("Missing output argument"); continue; }
        if ((flag.rfind("-D", 0) == 0 && flag.size() > 2) ||
            (flag.rfind("-U", 0) == 0 && flag.size() > 2) ||
            (flag.rfind("-std=", 0) == 0 && flag.size() > 5)) flags.push_back(flag);
        else if (flag.rfind("-I", 0) == 0 && flag.size() > 2) {
          auto include = fs::canonical(working / flag.substr(2));
          relativeInsideRoot(include, evidence.root);
          flags.push_back("-I" + include.string());
        } else throw std::runtime_error("Compiler argument outside passive allowlist");
      }
      tooling::FixedCompilationDatabase database(working.string(), flags);
      tooling::ClangTool tool(database, {source.string()});
      tool.appendArgumentsAdjuster(tooling::getInsertArgumentAdjuster(
        "--no-default-config", tooling::ArgumentInsertPosition::BEGIN));
      Diagnostics diagnostics(unitEvidence);
      Factory factory(unitEvidence);
      tool.setDiagnosticConsumer(&diagnostics);
      int result = tool.run(&factory);
      bool parsed = result == 0 && !diagnostics.errors;
      evidence.partial = evidence.partial || unitEvidence.partial || !parsed;
      evidence.diagnostics = std::min<unsigned>(64, evidence.diagnostics + unitEvidence.diagnostics);
      if (parsed) {
        for (auto &observation : unitEvidence.observations) {
          if (evidence.observations.size() == MaxObservations) {
            evidence.partial = true;
            break;
          }
          evidence.observations.push_back(std::move(observation));
        }
      }
      evidence.units.emplace_back(llvm::json::Object{{"file", name}, {"parsed", parsed}});
    }
    llvm::json::Array limitations;
    limitations.emplace_back("Build inclusion only; no runtime reachability or vulnerability verdict");
    if (evidence.partial) limitations.emplace_back("Parsing, diagnostic or observation limits made evidence partial");
    auto output = llvm::formatv("{0}\n", llvm::json::Value(llvm::json::Object{
      {"schema_version", "1.0"}, {"tool", "fuse-clang-analyzer"}, {"clang_version", CLANG_VERSION_STRING},
      {"status", evidence.partial ? "partial" : "completed"}, {"translation_units", std::move(evidence.units)},
      {"observations", std::move(evidence.observations)}, {"diagnostic_count", evidence.diagnostics},
      {"limitations", std::move(limitations)}})).str();
    if (output.size() > MaxBytes) throw std::runtime_error("Evidence JSON byte limit exceeded");
    std::cout << output;
    return 0;
  } catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 2; }
}
