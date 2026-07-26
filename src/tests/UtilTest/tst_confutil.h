#pragma once

#include <QSignalSpy>

#include <googletest.h>

#include <conf/addressgroup.h>
#include <conf/appgroup.h>
#include <conf/confrulemanager.h>
#include <conf/firewallconf.h>
#include <conf/rule.h>
#include <driver/drivercommon.h>
#include <log/logentryconn.h>
#include <manager/envmanager.h>
#include <util/conf/confappswalker.h>
#include <util/conf/confbuffer.h>
#include <util/conf/confruleswalker.h>
#include <util/conf/ifacetable.h>
#include <util/fileutil.h>
#include <util/net/netformatutil.h>
#include <util/net/netutil.h>
#include <util/stringutil.h>

#include <mocks/mocksqlitestmt.h>

class ConfUtilTest : public Test
{
    // Test interface
protected:
    void SetUp();
    void TearDown();
};

void ConfUtilTest::SetUp() { }

void ConfUtilTest::TearDown() { }

TEST_F(ConfUtilTest, confWriteRead)
{
    EnvManager envManager;
    FirewallConf conf;

    AddressGroup *inetGroup = conf.inetAddressGroup();

    inetGroup->setIncludeAll(true);
    inetGroup->setExcludeAll(false);

    inetGroup->setIncludeText(QString());
    inetGroup->setExcludeText(NetUtil::localIpNetworksText());

    conf.setAppBlockAll(true);
    conf.setAppAllowAll(false);

    AppGroup *appGroup1 = new AppGroup();
    appGroup1->setName("Base");
    appGroup1->setEnabled(true);
    appGroup1->setPeriodEnabled(true);
    appGroup1->setPeriodFrom("00:00");
    appGroup1->setPeriodTo("12:00");
    appGroup1->setBlockText("System");
    appGroup1->setAllowText("C:\\Program Files\\Skype\\Phone\\Skype.exe\n"
                            "?:\\Utils\\Dev\\Git\\**\n"
                            "D:\\**\\Programs\\**\n");

    AppGroup *appGroup2 = new AppGroup();
    appGroup2->setName("Browser");
    appGroup2->setEnabled(false);
    appGroup2->setAllowText("C:\\Utils\\Firefox\\Bin\\firefox.exe");
    appGroup2->setLimitInEnabled(true);
    appGroup2->setSpeedLimitIn(1024);

    conf.addAppGroup(appGroup1);
    conf.addAppGroup(appGroup2);

    conf.resetEdited(FirewallConf::AllEdited);
    conf.prepareToSave();

    ConfBuffer confBuf;

    if (!confBuf.writeConf(conf, nullptr, &envManager)) {
        qCritical() << "Error:" << confBuf.errorMessage();
        Q_UNREACHABLE();
    }

    // Check the buffer
    const char *data = confBuf.data() + DriverCommon::confIoConfOff();

    ASSERT_FALSE(DriverCommon::confIp4InRange(data, 0, true));
    ASSERT_FALSE(DriverCommon::confIp4InRange(data, NetFormatUtil::textToIp4("9.255.255.255")));
    ASSERT_FALSE(DriverCommon::confIp4InRange(data, NetFormatUtil::textToIp4("11.0.0.0")));
    ASSERT_TRUE(DriverCommon::confIp4InRange(data, NetFormatUtil::textToIp4("10.0.0.0")));
    ASSERT_TRUE(DriverCommon::confIp4InRange(data, NetFormatUtil::textToIp4("169.254.100.100")));
    ASSERT_TRUE(DriverCommon::confIp4InRange(data, NetFormatUtil::textToIp4("192.168.255.255")));
    ASSERT_FALSE(DriverCommon::confIp4InRange(data, NetFormatUtil::textToIp4("193.0.0.0")));
    ASSERT_TRUE(DriverCommon::confIp4InRange(data, NetFormatUtil::textToIp4("239.255.255.250")));
    ASSERT_TRUE(DriverCommon::confIp6InRange(data, NetFormatUtil::textToIp6("::1")));
    ASSERT_TRUE(DriverCommon::confIp6InRange(data, NetFormatUtil::textToIp6("::2")));
    ASSERT_TRUE(DriverCommon::confIp6InRange(data, NetFormatUtil::textToIp6("::ffff:0:2")));
    ASSERT_FALSE(DriverCommon::confIp6InRange(data, NetFormatUtil::textToIp6("65::")));

    ASSERT_TRUE(DriverCommon::confAppFind(data, "System").flags.found);

    ASSERT_TRUE(DriverCommon::confAppFind(data, "C:\\Program Files\\Skype\\Phone\\Skype.exe")
                    .flags.found);
    ASSERT_TRUE(DriverCommon::confAppFind(data, "C:\\Utils\\Dev\\Git\\git.exe").flags.found);
    ASSERT_TRUE(DriverCommon::confAppFind(data, "D:\\Utils\\Dev\\Git\\bin\\git.exe").flags.found);
    ASSERT_TRUE(DriverCommon::confAppFind(data, "D:\\My\\Programs\\Test.exe").flags.found);

    ASSERT_FALSE(DriverCommon::confAppFind(data, "C:\\Program Files\\Test.exe").flags.found);

    const auto firefoxData =
            DriverCommon::confAppFind(data, "C:\\Utils\\Firefox\\Bin\\firefox.exe");
    ASSERT_EQ(int(firefoxData.group_index), 1);
}

TEST_F(ConfUtilTest, checkEnvManager)
{
    EnvManager envManager;

    envManager.setCachedEnvVar("a", "a");
    envManager.setCachedEnvVar("b", "b");
    envManager.setCachedEnvVar("c", "c");

    ASSERT_EQ(envManager.expandString("%%%a%%b%%c%-%c%%b%%a%%%"), "%abc-cba%");

    envManager.setCachedEnvVar("d", "%e%");
    envManager.setCachedEnvVar("e", "%f%");
    envManager.setCachedEnvVar("f", "%d%");

    ASSERT_EQ(envManager.expandString("%d%"), QString());

    envManager.setCachedEnvVar("d", "%e%");
    envManager.setCachedEnvVar("e", "%f%");
    envManager.setCachedEnvVar("f", "%a%");

    ASSERT_EQ(envManager.expandString("%d%"), "a");

    // PATH is always set by the OS/process environment, unlike HOME which
    // may be undefined on some Windows CI runners.
    ASSERT_NE(envManager.expandString("%PATH%"), QString());
}

TEST_F(ConfUtilTest, rulesWriteRead)
{
    static Rule g_rules[] = {
        { .ruleId = 1, .ruleText = "1.1.1.1" },
        { .ruleId = 2, .ruleText = "2.2.2.2" },
        { .blocked = true, .ruleId = 3, .ruleText = "3.3.3.3" },
        { .ruleId = 4, .ruleText = "4.4.4.4" },
        { .ruleId = 5, .ruleText = "5.5.5.5" },
        { .ruleType = Rule::PresetRule, .ruleId = 6, .ruleText = "tcp(80)" },
        { .ruleType = Rule::PresetRule, .ruleId = 7, .ruleText = "udp(53)" },
        { .ruleType = Rule::PresetRule, .ruleId = 8, .ruleText = "dir(in)" },
        { .blocked = true, .ruleType = Rule::PresetRule, .ruleId = 9, .ruleText = "area(lan)" },
        { .blocked = true,
                .ruleType = Rule::PresetRule,
                .ruleId = 10,
                .ruleText = "area(localhost)" },
    };

    constexpr int MaxRuleId = 10;

    struct SubRule
    {
        quint16 ids[2]; // ruleId, subRuleId
    };

    static SubRule g_subRules[] = { // Sub Rules
        // Rule 1
        { 1, 6 }, { 1, 8 }, { 1, 9 },
        // Rule 2
        { 2, 7 },
        // Rule 5
        { 5, 7 }
    };

    class TestRules : public ConfRulesWalker
    {
    public:
        bool walkRules(
                WalkRulesArgs &wra, const std::function<walkRulesCallback> &func) const override
        {
            NiceMock<MockSqliteStmt> stmt;
            const int subRulesCount = std::size(g_subRules);
            int subRulesIndex = 0;

            ON_CALL(stmt, step).WillByDefault([&]() -> SqliteStmt::StepResult {
                return (++subRulesIndex < subRulesCount) ? SqliteStmt::StepRow
                                                         : SqliteStmt::StepDone;
            });

            ON_CALL(stmt, columnInt).WillByDefault([&](int column) -> qint32 {
                Q_ASSERT(column >= 0 && column <= 1);
                Q_ASSERT(subRulesIndex > 0 && subRulesIndex <= subRulesCount);

                const SubRule &subRule = g_subRules[subRulesIndex - 1];
                return subRule.ids[column];
            });

            wra.maxRuleId = MaxRuleId;

            ConfRuleManager::walkRulesMapByStmt(wra, stmt);

            return walkRulesLoop(func);
        }

    private:
        bool walkRulesLoop(const std::function<walkRulesCallback> &func) const
        {
            for (const auto &rule : g_rules) {
                if (!func(rule))
                    return false;
            }

            return true;
        }
    };

    TestRules testRules;

    ConfBuffer confBuf;

    if (!confBuf.writeRules(testRules)) {
        qCritical() << "Error:" << confBuf.errorMessage();
        Q_UNREACHABLE();
    }

    // Check the buffer
    const char *data = confBuf.data();

    // Allowed IP
    {
        FORT_CONF_META_CONN conn = {
            .inbound = true,
            .ip_proto = IpProto_TCP,
            .remote_port = 80,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("1.1.1.1") },
        };

        ASSERT_FALSE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }

    // Allowed IP
    {
        FORT_CONF_META_CONN conn = {
            .inbound = false,
            .ip_proto = IpProto_TCP,
            .remote_port = 80,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("4.4.4.4") },
        };

        ASSERT_FALSE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/4));
    }

    // Allowed Port
    {
        FORT_CONF_META_CONN conn = {
            .inbound = false,
            .ip_proto = IpProto_TCP,
            .remote_port = 80,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("3.3.3.3") },
        };

        ASSERT_FALSE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
        ASSERT_FALSE(conn.blocked);
    }

    // Allowed IP
    {
        FORT_CONF_META_CONN conn = {
            .inbound = false,
            .ip_proto = IpProto_UDP,
            .remote_port = 53,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("2.2.2.2") },
        };

        ASSERT_FALSE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/2));
    }

    // Blocked LocalHost
    {
        FORT_CONF_META_CONN conn = {
            .inbound = false,
            .is_loopback = true,
            .ip_proto = IpProto_TCP,
            .remote_port = 3128,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("127.0.0.1") },
        };

        ASSERT_TRUE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/10));
        ASSERT_TRUE(conn.blocked);
    }
}

TEST_F(ConfUtilTest, rulesOneFilter)
{
    static Rule g_rules[] = {
        { .blocked = true, .ruleId = 1, .ruleText = "1.1.1.1:80" },
    };

    class TestRules : public ConfRulesWalker
    {
    public:
        bool walkRules(
                WalkRulesArgs &wra, const std::function<walkRulesCallback> &func) const override
        {
            wra.maxRuleId = 1;

            return walkRulesLoop(func);
        }

    private:
        bool walkRulesLoop(const std::function<walkRulesCallback> &func) const
        {
            for (const auto &rule : g_rules) {
                if (!func(rule))
                    return false;
            }

            return true;
        }
    };

    TestRules testRules;

    ConfBuffer confBuf;

    if (!confBuf.writeRules(testRules)) {
        qCritical() << "Error:" << confBuf.errorMessage();
        Q_UNREACHABLE();
    }

    // Check the buffer
    const char *data = confBuf.data();

    // Blocked IP
    {
        FORT_CONF_META_CONN conn = {
            .inbound = false,
            .ip_proto = IpProto_TCP,
            .remote_port = 80,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("1.1.1.1") },
        };

        ASSERT_TRUE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }

    // Blocked IP, but Allowed Port
    {
        FORT_CONF_META_CONN conn = {
            .inbound = false,
            .ip_proto = IpProto_TCP,
            .remote_port = 443,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("1.1.1.1") },
        };

        ASSERT_FALSE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }

    // Allowed IP
    {
        FORT_CONF_META_CONN conn = {
            .inbound = true,
            .ip_proto = IpProto_TCP,
            .remote_port = 80,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("2.2.2.2") },
        };

        ASSERT_FALSE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }
}

TEST_F(ConfUtilTest, rulesTwoFilters)
{
    static Rule g_rules[] = {
        {
                .blocked = true,
                .ruleId = 1,
                .ruleText = "104.21.5.235:443\n"
                            "172.67.154.192\n"
                            "127.0.0.1:=local_ip:dir(IN)\n"
                            "=port(999)\n",
        },
        {
                .blocked = true,
                .ruleId = 2,
                .ruleText = "=ip()",
        },
    };

    class TestRules : public ConfRulesWalker
    {
    public:
        bool walkRules(
                WalkRulesArgs &wra, const std::function<walkRulesCallback> &func) const override
        {
            wra.maxRuleId = 2;

            return walkRulesLoop(func);
        }

    private:
        bool walkRulesLoop(const std::function<walkRulesCallback> &func) const
        {
            for (const auto &rule : g_rules) {
                if (!func(rule))
                    return false;
            }

            return true;
        }
    };

    TestRules testRules;

    ConfBuffer confBuf;

    if (!confBuf.writeRules(testRules)) {
        qCritical() << "Error:" << confBuf.errorMessage();
        Q_UNREACHABLE();
    }

    // Check the buffer
    const char *data = confBuf.data();

    // Allowed IP
    {
        FORT_CONF_META_CONN conn = {
            .ip_proto = IpProto_TCP,
            .remote_port = 80,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("2.2.2.2") },
        };

        ASSERT_FALSE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }

    // Blocked IP
    {
        FORT_CONF_META_CONN conn = {
            .ip_proto = IpProto_TCP,
            .remote_port = 443,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("104.21.5.235") },
        };

        ASSERT_TRUE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }

    // Blocked IP: Equal Local & Remote
    {
        const auto ip4 = NetFormatUtil::textToIp4("127.0.0.1");

        FORT_CONF_META_CONN conn = {
            .inbound = true,
            .ip_proto = IpProto_TCP,
            .local_ip = { .v4 = ip4 },
            .remote_ip = { .v4 = ip4 },
        };

        ASSERT_TRUE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }

    // Blocked Port: Equal Local & Remote
    {
        constexpr UINT16 port = 999;

        FORT_CONF_META_CONN conn = {
            .ip_proto = IpProto_UDP,
            .local_port = port,
            .remote_port = port,
        };

        ASSERT_TRUE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }

    // Blocked IP: Any Equal Local & Remote
    {
        const auto ip4 = NetFormatUtil::textToIp4("127.0.0.1");

        FORT_CONF_META_CONN conn = {
            .ip_proto = IpProto_TCP,
            .local_ip = { .v4 = ip4 },
            .remote_ip = { .v4 = ip4 },
        };

        ASSERT_TRUE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/2));
    }
}

TEST_F(ConfUtilTest, ruleExclusiveTerminating)
{
    static Rule g_rules[] = {
        {
                .blocked = false,
                .exclusive = true,
                .terminate = true,
                .terminateBlocked = true,
                .ruleId = 1,
                .ruleText = "dir(OUT):area(LOCALHOST)",
        },
    };

    class TestRules : public ConfRulesWalker
    {
    public:
        bool walkRules(
                WalkRulesArgs &wra, const std::function<walkRulesCallback> &func) const override
        {
            wra.maxRuleId = 1;

            return walkRulesLoop(func);
        }

    private:
        bool walkRulesLoop(const std::function<walkRulesCallback> &func) const
        {
            for (const auto &rule : g_rules) {
                if (!func(rule))
                    return false;
            }

            return true;
        }
    };

    TestRules testRules;

    ConfBuffer confBuf;

    if (!confBuf.writeRules(testRules)) {
        qCritical() << "Error:" << confBuf.errorMessage();
        Q_UNREACHABLE();
    }

    // Check the buffer
    const char *data = confBuf.data();

    // Allowed IP
    {
        FORT_CONF_META_CONN conn = {
            .is_loopback = true,
            .remote_port = 80,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("127.0.0.1") },
        };

        ASSERT_FALSE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }

    // Blocked IP
    {
        FORT_CONF_META_CONN conn = {
            .remote_port = 443,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("1.1.1.1") },
        };

        ASSERT_TRUE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }
}

TEST_F(ConfUtilTest, ruleFilterActionOption)
{
    static Rule g_rules[] = {
        {
                .blocked = false,
                .ruleId = 1,
                .ruleText = "dir(IN):act(BLOCK)\n"
                            "area(LOCALHOST):act(BLOCK)\n"
                            "{ act(BLOCK) }:opt(LOG, ALERT):port(111)\n",
        },
    };

    class TestRules : public ConfRulesWalker
    {
    public:
        bool walkRules(
                WalkRulesArgs &wra, const std::function<walkRulesCallback> &func) const override
        {
            wra.maxRuleId = 1;

            return walkRulesLoop(func);
        }

    private:
        bool walkRulesLoop(const std::function<walkRulesCallback> &func) const
        {
            for (const auto &rule : g_rules) {
                if (!func(rule))
                    return false;
            }

            return true;
        }
    };

    TestRules testRules;

    ConfBuffer confBuf;

    if (!confBuf.writeRules(testRules)) {
        qCritical() << "Error:" << confBuf.errorMessage();
        Q_UNREACHABLE();
    }

    // Check the buffer
    const char *data = confBuf.data();

    // Blocked Direction
    {
        FORT_CONF_META_CONN conn = {
            .inbound = true,
        };

        ASSERT_TRUE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }

    // Allowed Direction
    {
        FORT_CONF_META_CONN conn = {
            .inbound = false,
        };

        ASSERT_FALSE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }

    // Blocked IP
    {
        FORT_CONF_META_CONN conn = {
            .is_loopback = true,
            .remote_port = 80,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("127.0.0.1") },
        };

        ASSERT_TRUE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }

    // Allowed IP
    {
        FORT_CONF_META_CONN conn = {
            .remote_port = 80,
            .remote_ip = { .v4 = NetFormatUtil::textToIp4("1.1.1.1") },
        };

        ASSERT_FALSE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));
    }

    // Action in the block and Options
    {
        FORT_CONF_META_CONN conn = {
            .remote_port = 111,
        };

        ASSERT_TRUE(DriverCommon::confRulesConnBlocked(data, &conn, /*ruleId=*/1));

        ASSERT_TRUE(conn.conn_log);
        ASSERT_TRUE(conn.conn_alert);
    }
}

TEST_F(ConfUtilTest, ifaceTableBuildDeterministic)
{
    IfaceTable table;

    // Duplicates and a zero LUID must be dropped; result is sorted-unique
    table.build({ 0x300, 0x100, 0x200, 0x100, 0 });

    ASSERT_FALSE(table.isEmpty());
    ASSERT_EQ(table.count(), 3);

    // 1-based indexes follow the sorted order
    ASSERT_EQ(int(table.indexOf(0x100)), 1);
    ASSERT_EQ(int(table.indexOf(0x200)), 2);
    ASSERT_EQ(int(table.indexOf(0x300)), 3);

    // Unknown / none LUIDs map to 0
    ASSERT_EQ(int(table.indexOf(0)), 0);
    ASSERT_EQ(int(table.indexOf(0x999)), 0);

    const auto &ifaces = table.ifaces();
    ASSERT_EQ(ifaces.size(), 3);
    ASSERT_EQ(quint64(ifaces[0].luid), quint64(0x100));
    ASSERT_EQ(quint64(ifaces[1].luid), quint64(0x200));
    ASSERT_EQ(quint64(ifaces[2].luid), quint64(0x300));
}

TEST_F(ConfUtilTest, ifaceTableEmpty)
{
    IfaceTable table;

    table.build({ 0, 0 });

    ASSERT_TRUE(table.isEmpty());
    ASSERT_EQ(table.count(), 0);
    ASSERT_EQ(int(table.indexOf(0x100)), 0);
}

TEST_F(ConfUtilTest, confWriteIfaceTable)
{
    EnvManager envManager;
    FirewallConf conf;

    conf.resetEdited(FirewallConf::AllEdited);
    conf.prepareToSave();

    ConfBuffer confBuf;

    // Two referenced interfaces; sorted-unique -> indexes 1 and 2
    confBuf.buildIfaceTable({ 0x2000, 0x1000 });

    if (!confBuf.writeConf(conf, nullptr, &envManager)) {
        qCritical() << "Error:" << confBuf.errorMessage();
        Q_UNREACHABLE();
    }

    const char *data = confBuf.data() + DriverCommon::confIoConfOff();
    PCFORT_CONF drvConf = (PCFORT_CONF) data;

    ASSERT_EQ(int(drvConf->ifaces_n), 2);

    const PCFORT_CONF_IFACE iface1 = fort_conf_iface_ref(drvConf, 1);
    const PCFORT_CONF_IFACE iface2 = fort_conf_iface_ref(drvConf, 2);

    ASSERT_TRUE(iface1 != nullptr);
    ASSERT_TRUE(iface2 != nullptr);

    ASSERT_EQ(quint64(iface1->luid), quint64(0x1000));
    ASSERT_EQ(quint64(iface2->luid), quint64(0x2000));

    // Out-of-range references resolve to none
    ASSERT_TRUE(fort_conf_iface_ref(drvConf, 0) == nullptr);
    ASSERT_TRUE(fort_conf_iface_ref(drvConf, 3) == nullptr);
}
