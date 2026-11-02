#include <gtest/gtest.h>
#include <core/text_utils.h>

using namespace SysRecon::Core::Text;

// --- IPv4 parsing -----------------------------------------------------------

TEST(Ipv4, ParsesValidDottedQuad) {
    uint32_t ip = 0;
    ASSERT_TRUE(TryParseIpv4(L"192.168.10.200", ip));
    EXPECT_EQ(ip, 0xC0A80AC8u);
    ASSERT_TRUE(TryParseIpv4(L"0.0.0.0", ip));
    EXPECT_EQ(ip, 0u);
    ASSERT_TRUE(TryParseIpv4(L"255.255.255.255", ip));
    EXPECT_EQ(ip, 0xFFFFFFFFu);
}

TEST(Ipv4, RejectsOutOfRangeAndMalformed) {
    uint32_t ip = 0x12345678;
    EXPECT_FALSE(TryParseIpv4(L"999.999.999.999", ip));
    EXPECT_FALSE(TryParseIpv4(L"256.0.0.1", ip));
    EXPECT_FALSE(TryParseIpv4(L"1.2.3", ip));
    EXPECT_FALSE(TryParseIpv4(L"1.2.3.4.5", ip));
    EXPECT_FALSE(TryParseIpv4(L"1.2.3.4 ", ip));
    EXPECT_FALSE(TryParseIpv4(L"1..3.4", ip));
    EXPECT_FALSE(TryParseIpv4(L"0001.2.3.4", ip));
    EXPECT_FALSE(TryParseIpv4(L"", ip));
    EXPECT_FALSE(TryParseIpv4(L"a.b.c.d", ip));
    // `out` is untouched on failure.
    EXPECT_EQ(ip, 0x12345678u);
}

TEST(Ipv4, ClassifiesPrivateRanges) {
    EXPECT_TRUE(IsPrivateIpv4(L"10.0.0.1"));
    EXPECT_TRUE(IsPrivateIpv4(L"172.16.0.1"));
    EXPECT_TRUE(IsPrivateIpv4(L"172.31.255.255"));
    EXPECT_FALSE(IsPrivateIpv4(L"172.32.0.1"));
    EXPECT_FALSE(IsPrivateIpv4(L"172.15.0.1"));
    EXPECT_TRUE(IsPrivateIpv4(L"192.168.0.1"));
    EXPECT_TRUE(IsPrivateIpv4(L"169.254.1.1"));
    EXPECT_FALSE(IsPrivateIpv4(L"8.8.8.8"));
    EXPECT_FALSE(IsPrivateIpv4(L"not-an-ip"));
}

TEST(Ipv4, DetectsLoopback) {
    EXPECT_TRUE(IsLoopbackIpv4(L"127.0.0.1"));
    EXPECT_TRUE(IsLoopbackIpv4(L"127.10.0.1"));
    EXPECT_FALSE(IsLoopbackIpv4(L"0.0.0.0"));
    EXPECT_FALSE(IsLoopbackIpv4(L"10.0.0.1"));
}

// --- Registry string decoding ----------------------------------------------
// Registry data is attacker-controlled. The policy reader used to cast the raw
// buffer to WCHAR* and read until a NUL that need not exist.

TEST(RegistryBuffer, StopsAtTerminator) {
    const wchar_t data[] = L"abc\0junk";
    EXPECT_EQ(RegistryBufferToString(data, sizeof(data)), L"abc");
}

TEST(RegistryBuffer, NeverReadsPastByteCountWhenUnterminated) {
    const wchar_t data[4] = {L'a', L'b', L'c', L'd'};  // No terminator at all.
    EXPECT_EQ(RegistryBufferToString(data, 3 * sizeof(wchar_t)), L"abc");
    EXPECT_EQ(RegistryBufferToString(data, sizeof(data)), L"abcd");
}

TEST(RegistryBuffer, IgnoresTrailingOddByte) {
    const wchar_t data[] = {L'x', L'y'};
    EXPECT_EQ(RegistryBufferToString(data, sizeof(wchar_t) + 1), L"x");
}

TEST(RegistryBuffer, HandlesEmptyAndNull) {
    const wchar_t data[] = {L'\0'};
    EXPECT_EQ(RegistryBufferToString(data, 0), L"");
    EXPECT_EQ(RegistryBufferToString(data, 1), L"");
    EXPECT_EQ(RegistryBufferToString(nullptr, 100), L"");
}

// --- File-name sanitising ---------------------------------------------------
// Dump files are named after the (attacker-chosen) process name.

TEST(SanitizeFileName, ReplacesPathAndReservedCharacters) {
    EXPECT_EQ(SanitizeFileName(L"..\\..\\Windows\\evil.exe"), L"___.._Windows_evil.exe");
    EXPECT_EQ(SanitizeFileName(L"a/b:c*d?e\"f<g>h|i"), L"a_b_c_d_e_f_g_h_i");
}

TEST(SanitizeFileName, NeutralisesDotNames) {
    EXPECT_EQ(SanitizeFileName(L".."), L"__");
    EXPECT_EQ(SanitizeFileName(L".hidden"), L"_hidden");
}

TEST(SanitizeFileName, KeepsOrdinaryNamesAndCapsLength) {
    EXPECT_EQ(SanitizeFileName(L"notepad.exe"), L"notepad.exe");
    EXPECT_EQ(SanitizeFileName(L""), L"unnamed");
    EXPECT_EQ(SanitizeFileName(WString(200, L'a')).size(), 64u);
}

// --- DACL decisions ---------------------------------------------------------
// Real masks from default Windows security descriptors. The service check used
// `mask & SERVICE_ALL_ACCESS`, true for any right at all, which produced ~260
// Critical "weak service permissions" findings on a clean Windows install.

TEST(ServiceDacl, ReadAndControlRightsAreNotReconfiguration) {
    // CCLCSWLOCRRC: the standard grant to INTERACTIVE / Authenticated Users.
    EXPECT_FALSE(GrantsServiceReconfiguration(0x0002018D));
    // + RP/WP (start/stop): still not a privilege escalation.
    EXPECT_FALSE(GrantsServiceReconfiguration(0x000201FD));
    EXPECT_FALSE(GrantsServiceReconfiguration(0x80000000));  // GENERIC_READ
    EXPECT_FALSE(GrantsServiceReconfiguration(0));
}

TEST(ServiceDacl, ReconfigurationRightsAreFlagged) {
    EXPECT_TRUE(GrantsServiceReconfiguration(0x00000002));  // SERVICE_CHANGE_CONFIG
    EXPECT_TRUE(GrantsServiceReconfiguration(0x00040000));  // WRITE_DAC
    EXPECT_TRUE(GrantsServiceReconfiguration(0x00080000));  // WRITE_OWNER
    EXPECT_TRUE(GrantsServiceReconfiguration(0x000F01FF));  // SERVICE_ALL_ACCESS
    EXPECT_TRUE(GrantsServiceReconfiguration(0x10000000));  // GENERIC_ALL
    EXPECT_TRUE(GrantsServiceReconfiguration(0x40000000));  // GENERIC_WRITE
}

TEST(FileDacl, ReadExecuteIsNotModification) {
    EXPECT_FALSE(GrantsFileModification(0x001200A9));  // Read & execute
    EXPECT_FALSE(GrantsFileModification(0x00120089));  // Read
    EXPECT_FALSE(GrantsFileModification(0x00000100));  // FILE_WRITE_ATTRIBUTES only
    EXPECT_FALSE(GrantsFileModification(0x00000010));  // FILE_WRITE_EA only
    EXPECT_FALSE(GrantsFileModification(0x00010000));  // DELETE only
}

TEST(FileDacl, WriteRightsAreModification) {
    EXPECT_TRUE(GrantsFileModification(0x001301BF));  // Modify
    EXPECT_TRUE(GrantsFileModification(0x001F01FF));  // Full control
    EXPECT_TRUE(GrantsFileModification(0x00000002));  // FILE_WRITE_DATA / add file
    EXPECT_TRUE(GrantsFileModification(0x00000004));  // FILE_APPEND_DATA / add subdirectory
    EXPECT_TRUE(GrantsFileModification(0x00040000));  // WRITE_DAC
    EXPECT_TRUE(GrantsFileModification(0x40000000));  // GENERIC_WRITE
}

TEST(AceFlags, InheritOnlyAcesDoNotApplyToTheObject) {
    EXPECT_TRUE(AceAppliesToObject(0x00));
    EXPECT_TRUE(AceAppliesToObject(0x03));   // OBJECT_INHERIT | CONTAINER_INHERIT
    EXPECT_FALSE(AceAppliesToObject(0x08));  // INHERIT_ONLY
    EXPECT_FALSE(AceAppliesToObject(0x0B));  // OI | CI | IO
    EXPECT_TRUE(AceAppliesToObject(0x10));   // INHERITED_ACE alone still applies
}

// --- Event log XML ------------------------------------------------------------

namespace {
// Shape of a real event 4732 rendered with EvtRenderEventXml.
const wchar_t* kEvent4732 =
    L"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    L"<Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625}'/>"
    L"<EventID>4732</EventID><TimeCreated SystemTime='2026-11-01T10:15:30.1234567Z'/>"
    L"<Computer>HOST</Computer></System><EventData>"
    L"<Data Name='MemberName'>-</Data><Data Name='MemberSid'>S-1-5-21-1-2-3-1001</Data>"
    L"<Data Name='TargetUserName'>Administrators</Data>"
    L"<Data Name='TargetSid'>S-1-5-32-544</Data>"
    L"<Data Name='SubjectUserName'>a&amp;b &lt;x&gt;</Data>"
    L"<Data Name='Empty'/>"
    L"</EventData></Event>";
}  // namespace

TEST(EventXml, ReadsElementsDataAndAttributes) {
    EXPECT_EQ(XmlElementText(kEvent4732, L"EventID"), L"4732");
    EXPECT_EQ(XmlElementText(kEvent4732, L"Computer"), L"HOST");
    EXPECT_EQ(EventDataValue(kEvent4732, L"TargetSid"), L"S-1-5-32-544");
    EXPECT_EQ(EventDataValue(kEvent4732, L"MemberSid"), L"S-1-5-21-1-2-3-1001");
    EXPECT_EQ(EventDataValue(kEvent4732, L"SubjectUserName"), L"a&b <x>");
    EXPECT_EQ(XmlAttribute(kEvent4732, L"TimeCreated", L"SystemTime"), L"2026-11-01T10:15:30.1234567Z");
    EXPECT_EQ(XmlAttribute(kEvent4732, L"Provider", L"Name"), L"Microsoft-Windows-Security-Auditing");
}

TEST(EventXml, MissingOrMalformedYieldsEmpty) {
    EXPECT_EQ(EventDataValue(kEvent4732, L"Empty"), L"");
    EXPECT_EQ(EventDataValue(kEvent4732, L"Nope"), L"");
    EXPECT_EQ(XmlElementText(L"<A>unterminated", L"A"), L"");
    EXPECT_EQ(XmlElementText(L"<A/>", L"A"), L"");
    EXPECT_EQ(XmlAttribute(L"<T a='1'>", L"T", L"b"), L"");
    EXPECT_EQ(XmlAttribute(L"<T xa='1' a=\"2\">", L"T", L"a"), L"2");
    // A longer element name never matches a prefix of it.
    EXPECT_EQ(XmlElementText(L"<UserNameX>no</UserNameX><UserName>yes</UserName>", L"UserName"), L"yes");
    // Data Name markers outside a <Data> tag are ignored.
    EXPECT_EQ(EventDataValue(L"<X Name='k'>bad</X><Data Name=\"k\">good</Data>", L"k"), L"good");
}

TEST(EventXml, DecodesEntities) {
    EXPECT_EQ(XmlDecode(L"&lt;&gt;&amp;&quot;&apos;"), L"<>&\"'");
    EXPECT_EQ(XmlDecode(L"&#65;&#x42;"), L"AB");
    EXPECT_EQ(XmlDecode(L"&unknown; & &#; &#xZZ;"), L"&unknown; & &#; &#xZZ;");
    EXPECT_EQ(XmlDecode(L"&#0;"), L"&#0;");
}

TEST(EventXml, ServiceInstallSeverity) {
    EXPECT_EQ(ServiceInstallSeverity(L"%SystemRoot%\\System32\\svchost.exe -k netsvcs"), 0);
    EXPECT_EQ(ServiceInstallSeverity(L"\"C:\\Program Files\\Vendor\\agent.exe\""), 0);
    EXPECT_EQ(ServiceInstallSeverity(
        L"\"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.1\\MsMpEng.exe\""), 0);
    EXPECT_EQ(ServiceInstallSeverity(L"C:\\Users\\bob\\AppData\\Roaming\\x\\svc.exe"), 2);
    EXPECT_EQ(ServiceInstallSeverity(L"C:\\Windows\\Temp\\psexesvc.exe"), 2);
    EXPECT_EQ(ServiceInstallSeverity(L"\\\\10.0.0.5\\share\\svc.exe"), 2);
    // Metasploit/Impacket-style service: %COMSPEC% /b /c start ...
    EXPECT_EQ(ServiceInstallSeverity(L"%COMSPEC% /b /c start /b /min powershell.exe -nop"), 3);
    EXPECT_EQ(ServiceInstallSeverity(L"%COMSPEC% /c echo x > \\\\.\\pipe\\y"), 3);
    EXPECT_EQ(ServiceInstallSeverity(L"cmd.exe /c whoami"), 3);
    EXPECT_EQ(ServiceInstallSeverity(L"C:\\Windows\\System32\\cmd.exe /c x"), 3);
    EXPECT_EQ(ServiceInstallSeverity(
        L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -nop -w hidden"), 3);
    EXPECT_EQ(ServiceInstallSeverity(L"C:\\x\\loader.exe -enc SQBFAFgA"), 3);
    EXPECT_EQ(ServiceInstallSeverity(L"rundll32.exe C:\\x.dll,Entry"), 3);
}

TEST(EventXml, PrivilegedGroupSids) {
    EXPECT_TRUE(IsPrivilegedGroupSid(L"S-1-5-32-544"));
    EXPECT_TRUE(IsPrivilegedGroupSid(L"s-1-5-32-555"));
    EXPECT_TRUE(IsPrivilegedGroupSid(L"S-1-5-21-1004336348-1177238915-682003330-512"));
    EXPECT_TRUE(IsPrivilegedGroupSid(L"S-1-5-21-1-2-3-519"));
    EXPECT_FALSE(IsPrivilegedGroupSid(L"S-1-5-32-545"));            // Users
    EXPECT_FALSE(IsPrivilegedGroupSid(L"S-1-5-21-1-2-3-513"));      // Domain Users
    EXPECT_FALSE(IsPrivilegedGroupSid(L"S-1-5-21-1-2-3-5120"));
    EXPECT_FALSE(IsPrivilegedGroupSid(L""));
}

TEST(EventXml, RecommendedLogSizes) {
    EXPECT_EQ(RecommendedLogSizeKb(L"Security"), 196608u);
    EXPECT_EQ(RecommendedLogSizeKb(L"system"), 32768u);
    EXPECT_EQ(RecommendedLogSizeKb(L"Application"), 32768u);
    EXPECT_EQ(RecommendedLogSizeKb(L"Microsoft-Windows-PowerShell/Operational"), 0u);
}

// --- Firewall rules -------------------------------------------------------------

TEST(FirewallRules, PortLists) {
    EXPECT_TRUE(PortListIncludes(L"*", 3389));
    EXPECT_TRUE(PortListIncludes(L"80, 443,3389", 3389));
    EXPECT_TRUE(PortListIncludes(L"5000-6000", 5985));
    EXPECT_FALSE(PortListIncludes(L"5000-5900", 5985));
    EXPECT_FALSE(PortListIncludes(L"RPC", 135));
    EXPECT_FALSE(PortListIncludes(L"RPC-EPMap,Ply2Disc", 135));
    EXPECT_FALSE(PortListIncludes(L"", 22));
    EXPECT_FALSE(PortListIncludes(L"99999", 22));
}

TEST(FirewallRules, Severity) {
    FirewallRuleView open;
    open.enabled = open.inbound = open.allow = true;
    open.remote_addresses = L"*";
    open.local_ports = L"*";
    EXPECT_EQ(FirewallRuleSeverity(open), 3);

    FirewallRuleView app = open;
    app.application = L"C:\\Program Files\\App\\app.exe";
    app.public_profile = true;
    EXPECT_EQ(FirewallRuleSeverity(app), 0);  // Program-scoped any-port rule.

    // Built-in Store-app rules (Microsoft.Windows.ShellExperienceHost, ...):
    // no program path, scoped by package SID. Real Windows CI flagged ~20 of
    // these as "allows all traffic" before the package scope was read.
    FirewallRuleView package = open;
    package.app_package = L"S-1-15-2-1430448594-2639229838-973813799-439329657";
    package.public_profile = true;
    EXPECT_EQ(FirewallRuleSeverity(package), 0);

    // What CI actually saw on Windows Server 2025: the Store-app rules report
    // no package but are owned by SYSTEM or the installing administrator.
    FirewallRuleView owned = open;
    owned.local_user_owner = L"S-1-5-18";
    EXPECT_EQ(FirewallRuleSeverity(owned), 0);
    owned.local_user_owner = L"S-1-5-21-3077485881-3661871218-4154919024-500";
    EXPECT_EQ(FirewallRuleSeverity(owned), 0);

    FirewallRuleView rdp = open;
    rdp.local_ports = L"3389";
    rdp.protocol = 6;
    rdp.service = L"TermService";
    EXPECT_EQ(FirewallRuleSeverity(rdp), 0);  // Not on the Public profile.
    rdp.public_profile = true;
    EXPECT_EQ(FirewallRuleSeverity(rdp), 2);
    rdp.remote_addresses = L"LocalSubnet";
    EXPECT_EQ(FirewallRuleSeverity(rdp), 0);

    FirewallRuleView icmp = open;
    icmp.protocol = 1;
    EXPECT_EQ(FirewallRuleSeverity(icmp), 0);

    FirewallRuleView disabled = open;
    disabled.enabled = false;
    EXPECT_EQ(FirewallRuleSeverity(disabled), 0);
    FirewallRuleView block = open;
    block.allow = false;
    EXPECT_EQ(FirewallRuleSeverity(block), 0);
    FirewallRuleView outbound = open;
    outbound.inbound = false;
    EXPECT_EQ(FirewallRuleSeverity(outbound), 0);
}
