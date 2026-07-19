/* Fort Firewall Callouts */

#include "fortcout.h"

#include "common/fortdef.h"
#include "common/fortguid.h"
#include "common/fortprov.h"

#include "fortcnf_conf.h"
#include "fortcnf_rule.h"
#include "fortcnf_zone.h"
#include "fortcoutarg.h"
#include "fortdbg.h"
#include "fortdev.h"
#include "fortps.h"
#include "forttrace.h"
#include "fortutl.h"

static struct
{
    FWPS_CALLOUT0 ale_callouts[FORT_STAT_ALE_CALLOUT_IDS_COUNT];
    FWPS_CALLOUT0 packet_callouts[FORT_STAT_PACKET_CALLOUT_IDS_COUNT];
    FWPS_CALLOUT0 discard_callouts[FORT_STAT_DISCARD_CALLOUT_IDS_COUNT];
} g_calloutGlobal;

#define FORT_REDIRECT_CALLOUTS_COUNT 2

static struct
{
    FWPS_CALLOUT3 callouts[FORT_REDIRECT_CALLOUTS_COUNT];
    UINT32 callout_ids[FORT_REDIRECT_CALLOUTS_COUNT];
    HANDLE redirect_handle;
} g_redirectGlobal;

static void fort_callout_classify_block(FWPS_CLASSIFY_OUT0 *classifyOut)
{
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

static void fort_callout_classify_drop(FWPS_CLASSIFY_OUT0 *classifyOut)
{
    classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

    fort_callout_classify_block(classifyOut);
}

static void fort_callout_classify_permit(
        const FWPS_FILTER0 *filter, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    classifyOut->actionType = FWP_ACTION_PERMIT;
    if ((filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)) {
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

static void fort_callout_classify_continue(FWPS_CLASSIFY_OUT0 *classifyOut)
{
    classifyOut->actionType = FWP_ACTION_CONTINUE;
}

inline static void fort_callout_ale_set_app_flags(
        PFORT_CONF_META_CONN conn, const FORT_APP_DATA app_data)
{
    conn->app_data_filled = TRUE;
    conn->app_data = app_data;
}

inline static void fort_callout_ale_fill_meta_path_real(PFORT_CONF_META_CONN conn,
        const FWP_BYTE_BLOB processPath, const FORT_APP_PATH_DRIVE ps_drive)
{
    PFORT_PATH_BUFFER pb = &conn->path_buf;
    PFORT_APP_PATH path = &pb->path;

    if (processPath.size > FORT_PATH_BUFFER_DATA_MIN_SIZE) {
        if (!fort_path_buffer_alloc(pb, processPath.size))
            return;

        path->buffer = pb->buffer;
    } else {
        path->buffer = pb->data;
    }

    path->len = (UINT16) (processPath.size - sizeof(WCHAR)); /* chop terminating zero */

    RtlCopyMemory((PVOID) path->buffer, processPath.data, processPath.size);

    fort_path_drive_adjust(path, ps_drive);

    conn->real_path = *path;
}

static void fort_callout_ale_fill_meta_path(PCFORT_CALLOUT_ARG ca, PFORT_CONF_META_CONN conn)
{
    const FWP_BYTE_BLOB processPath = *ca->inMetaValues->processPath;

    PFORT_APP_PATH path = &conn->path;

    path->len = (UINT16) (processPath.size - sizeof(WCHAR)); /* chop terminating zero */
    path->buffer = (PCWSTR) processPath.data;

    PFORT_APP_PATH real_path = &conn->real_path;
    *real_path = *path;

    FORT_PS_OPT ps_opt = { 0 };

    if (fort_pstree_get_proc_name(&fort_device()->ps_tree, conn->process_id, path, &ps_opt)) {

        const BOOL inherited = (ps_opt.flags & FORT_PSNODE_NAME_INHERITED) != 0;
        if (!inherited) {
            *real_path = *path;
            return;
        }

        conn->inherited = TRUE;
    }

    fort_callout_ale_fill_meta_path_real(conn, processPath, ps_opt.path_drive);

    if (!conn->inherited) {
        *path = *real_path;
    }
}

static void fort_callout_fill_meta_ip(PCFORT_CALLOUT_ARG ca, UCHAR ipIndex, ip_addr_t *ip)
{
    const FWP_VALUE0 value = ca->inFixedValues->incomingValue[ipIndex].value;

    if (ca->isIPv6) {
        RtlCopyMemory(ip->v6.data, value.byteArray16, sizeof(ip6_addr_t));
    } else {
        ip->v4 = value.uint32;
    }
}

inline static void fort_callout_ale_fill_meta_conn_proc(
        PCFORT_CALLOUT_ARG ca, PFORT_CONF_META_CONN conn)
{
    conn->process_id = (UINT32) ca->inMetaValues->processId;
}

static void fort_callout_ale_fill_meta_conn(PCFORT_CALLOUT_ARG ca, PFORT_CONF_META_CONN conn)
{
    if (conn->conn_filled)
        return;

    conn->conn_filled = TRUE;

    conn->flow_id = ca->inMetaValues->flowHandle;

    conn->profile_id = ca->inFixedValues->incomingValue[ca->fi->profileId].value.uint8;

    conn->ip_proto = ca->inFixedValues->incomingValue[ca->fi->ipProto].value.uint8;

    conn->local_port = ca->inFixedValues->incomingValue[ca->fi->localPort].value.uint16;
    conn->remote_port = ca->inFixedValues->incomingValue[ca->fi->remotePort].value.uint16;

    fort_callout_fill_meta_ip(ca, ca->fi->localIp, &conn->local_ip);
}

static FORT_APP_DATA fort_callout_ale_conf_app_data(
        PCFORT_CALLOUT_ARG ca, PFORT_CONF_META_CONN conn, PFORT_CONF_REF conf_ref)
{
    if (conn->app_data_filled) {
        return conn->app_data;
    }

    fort_callout_ale_fill_meta_path(ca, conn);

    const FORT_APP_DATA app_data =
            fort_conf_app_find(&conf_ref->conf, &conn->path, fort_conf_exe_find, conf_ref);

    fort_callout_ale_set_app_flags(conn, app_data);

    return app_data;
}

inline static BOOL fort_callout_ale_associate_flow(
        PFORT_CALLOUT_ALE_EXTRA cx, PFORT_CONF_META_CONN conn)
{
    BOOL proc_stat = FALSE;

    const NTSTATUS status = fort_flow_associate(&fort_device()->stat, conn, &proc_stat);

    if (!NT_SUCCESS(status)) {
        if (status != FORT_STATUS_FLOW_BLOCK) {
            LOG("Classify v4: Flow assoc. error: %x\n", status);
            TRACE(FORT_CALLOUT_FLOW_ASSOC_ERROR, status, 0, 0);
        }

        conn->reason = FORT_CONN_REASON_REAUTH;
        return TRUE; /* block (Error) */
    }

    if (!proc_stat) {
        fort_buffer_conn_write(
                &fort_device()->buffer, conn, &cx->irp_info, FORT_BUFFER_CONN_WRITE_PROC_NEW);
    }

    return FALSE;
}

inline static BOOL fort_callout_ale_log_app_path_check(
        FORT_CONF_FLAGS conf_flags, const FORT_APP_DATA app_data)
{
    return app_data.flags.found == 0 && conf_flags.filter_enabled
            && (conf_flags.allow_all_new || conf_flags.log_app);
}

inline static void fort_callout_ale_log_app_path(PFORT_CALLOUT_ALE_EXTRA cx,
        PFORT_CONF_REF conf_ref, const FORT_CONF_FLAGS conf_flags, FORT_APP_DATA app_data)
{
    PFORT_CONF_META_CONN conn = &cx->conn;

    if (conn->ignore || !fort_callout_ale_log_app_path_check(conf_flags, app_data))
        return;

    app_data.flags.log_stat = TRUE;
    app_data.flags.log_allowed_conn = TRUE;
    app_data.flags.log_blocked_conn = TRUE;
    app_data.flags.blocked = !(conf_flags.allow_all_new || conf_flags.app_allow_all);

    app_data.flags.is_new = TRUE;
    app_data.flags.found = TRUE;
    app_data.flags.alerted = TRUE;

    const FORT_APP_ENTRY app_entry = {
        .app_data = app_data,
        .path_len = conn->path.len,
    };

    if (!NT_SUCCESS(fort_conf_ref_exe_add_path(conf_ref, &app_entry, &conn->path)))
        return;

    fort_callout_ale_set_app_flags(conn, app_data);

    fort_buffer_conn_write(&fort_device()->buffer, conn, &cx->irp_info, FORT_BUFFER_CONN_WRITE_APP);
}

inline static BOOL fort_callout_ale_log_conn_check_app(
        PFORT_CONF_META_CONN conn, const FORT_APP_DATA app_data, const FORT_CONF_FLAGS conf_flags)
{
    const BOOL log_conn = app_data.flags.found == 0
            || (conn->blocked ? app_data.flags.log_blocked_conn : app_data.flags.log_allowed_conn);

    if (!log_conn)
        return FALSE;

    conn->conn_alert |= app_data.flags.alerted;

    const BOOL log_alert = (conn->conn_alert || !conf_flags.log_alerted_conn);

    return log_alert && !conn->conn_nolog;
}

inline static BOOL fort_callout_ale_log_conn_check(PCFORT_CALLOUT_ARG ca, PFORT_CONF_META_CONN conn,
        PFORT_CONF_REF conf_ref, const FORT_CONF_FLAGS conf_flags)
{
    if (conn->ignore || conn->reason == FORT_CONN_REASON_UNKNOWN)
        return FALSE;

    /* Conf */
    {
        const BOOL log_conn =
                (conn->blocked ? conf_flags.log_blocked_conn : conf_flags.log_allowed_conn);

        if (!(log_conn || conn->ask_to_connect))
            return FALSE;
    }

    /* App */
    {
        const FORT_APP_DATA app_data = fort_callout_ale_conf_app_data(ca, conn, conf_ref);

        return fort_callout_ale_log_conn_check_app(conn, app_data, conf_flags);
    }
}

inline static BOOL fort_callout_ale_add_pending(PCFORT_CALLOUT_ARG ca, PFORT_CONF_META_CONN conn)
{
    if (!fort_pending_add_packet(&fort_device()->pending, ca, conn)) {
        conn->reason = FORT_CONN_REASON_ASK_LIMIT;
        return TRUE; /* block (Error) */
    }

    conn->drop_blocked = TRUE;
    conn->reason = FORT_CONN_REASON_ASK_PENDING;
    return TRUE; /* drop (Pending) */
}

inline static BOOL fort_callout_ale_process_flow(
        PCFORT_CALLOUT_ARG ca, PFORT_CALLOUT_ALE_EXTRA cx, const FORT_CONF_FLAGS conf_flags)
{
    PFORT_CONF_META_CONN conn = &cx->conn;

    if (conn->ask_to_connect) {
        return fort_callout_ale_add_pending(ca, conn);
    }

    if (!conf_flags.log_stat)
        return FALSE;

    return fort_callout_ale_associate_flow(cx, conn);
}

inline static BOOL fort_callout_ale_conn_zone_filtered(
        PFORT_CONF_META_CONN conn, const FORT_APP_DATA app_data)
{
    if (app_data.zones.accept_mask == 0 && app_data.zones.reject_mask == 0)
        return FALSE;

    FORT_CONF_ZONES_CONN_FILTERED_OPT opt = {
        .rule_zones = app_data.zones,
    };

    if (fort_devconf_zones_conn_filtered(&fort_device()->conf, conn, &opt)) {
        if (opt.reject.included) {
            conn->zone_id = opt.reject.zone_id;
            conn->blocked = TRUE;
            return TRUE; /* block Rejected Zones */
        }

        if (opt.accept.filtered) {
            conn->zone_id = opt.accept.zone_id;
            conn->blocked = !opt.accept.included;
            return TRUE; /* allow/block-not Accepted Zones */
        }
    }

    return FALSE;
}

inline static BOOL fort_callout_ale_conn_rule_filtered(
        PFORT_CONF_META_CONN conn, UINT16 rule_id, UCHAR reason)
{
    if (rule_id == 0)
        return FALSE;

    if (fort_devconf_rules_conn_filtered(&fort_device()->conf, conn, rule_id)) {
        if (conn->rule_id == 0) {
            conn->rule_id = rule_id;
        }
        conn->reason = reason;
        return TRUE;
    }

    return FALSE;
}

inline static BOOL fort_callout_ale_app_flags_blocked(
        PFORT_CONF_META_CONN conn, const FORT_CONF_FLAGS conf_flags, const FORT_APP_DATA app_data)
{
    if (app_data.flags.blocked) {
        conn->reason = FORT_CONN_REASON_PROGRAM;
        return TRUE; /* block Program */
    }

    if (app_data.flags.lan_only && !conn->is_local_net) {
        conn->reason = FORT_CONN_REASON_LAN_ONLY;
        return TRUE; /* block LAN Only */
    }

    if (fort_conf_app_group_blocked(conf_flags, app_data)) {
        conn->reason = FORT_CONN_REASON_APP_GROUP;
        return TRUE; /* block Group */
    }

    return FALSE;
}

static BOOL fort_callout_ale_app_filtered(
        PFORT_CONF_META_CONN conn, const FORT_CONF_FLAGS conf_flags, const FORT_APP_DATA app_data)
{
    if (fort_callout_ale_app_flags_blocked(conn, conf_flags, app_data)) {
        conn->blocked = TRUE;
        return TRUE; /* filtered by App Flags */
    }

    if (fort_callout_ale_conn_zone_filtered(conn, app_data)) {
        conn->reason = FORT_CONN_REASON_ZONE;
        return TRUE; /* filtered by Zones */
    }

    return fort_callout_ale_conn_rule_filtered(conn, app_data.rule_id, FORT_CONN_REASON_RULE);
}

inline static void fort_callout_ale_filter(
        PFORT_CONF_META_CONN conn, const FORT_CONF_FLAGS conf_flags, const FORT_APP_DATA app_data)
{
    const FORT_CONF_RULES_GLOB rules_glob = fort_device()->conf.rules_glob;

    if (fort_callout_ale_conn_rule_filtered(
                conn, rules_glob.pre_rule_id, FORT_CONN_REASON_RULE_GLOB_PRE)) {
        return; /* filtered by Global Rule Pre Apps */
    }

    const BOOL app_found = (app_data.flags.found != 0);
    if (app_found ? fort_callout_ale_app_filtered(conn, conf_flags, app_data) : conn->blocked) {
        return; /* filtered by App or Filter Mode */
    }

    if (fort_callout_ale_conn_rule_filtered(
                conn, rules_glob.post_rule_id, FORT_CONN_REASON_RULE_GLOB_POST)) {
        return; /* filtered by Global Rule Post Apps */
    }

    if (app_found) {
        conn->blocked = FALSE; /* allow App */
        conn->reason = FORT_CONN_REASON_PROGRAM;
    }
}

inline static BOOL fort_callout_ale_filter_mode_filtered(
        PFORT_CONF_META_CONN conn, const FORT_CONF_FLAGS conf_flags)
{
    conn->reason = FORT_CONN_REASON_FILTER_MODE;

    /* Auto-Learn */
    if (conf_flags.allow_all_new) {
        conn->blocked = FALSE;
        return FALSE;
    }

    /* Ask to Connect */
    if (conf_flags.ask_to_connect) {
        conn->blocked = FALSE;
        conn->ask_to_connect = TRUE;
        return TRUE;
    }

    /* Block/Allow All */
    if (conf_flags.app_block_all || conf_flags.app_allow_all) {
        conn->blocked = (UINT16) conf_flags.app_block_all;
        return FALSE;
    }

    /* Ignore */
    conn->blocked = TRUE;
    conn->ignore = TRUE;
    return TRUE;
}

inline static BOOL fort_callout_ale_allowed(
        PFORT_CONF_META_CONN conn, const FORT_CONF_FLAGS conf_flags, const FORT_APP_DATA app_data)
{
    if (!conn->blocked)
        return TRUE; /* collect traffic, when Filter Disabled */

    const BOOL app_found = (app_data.flags.found != 0);
    if (app_found || !fort_callout_ale_filter_mode_filtered(conn, conf_flags)) {
        fort_callout_ale_filter(conn, conf_flags, app_data);
    }

    return !conn->blocked;
}

inline static void fort_callout_ale_check_app(PCFORT_CALLOUT_ARG ca, PFORT_CALLOUT_ALE_EXTRA cx,
        PFORT_CONF_REF conf_ref, const FORT_CONF_FLAGS conf_flags)
{
    PFORT_CONF_META_CONN conn = &cx->conn;

    const FORT_APP_DATA app_data = fort_callout_ale_conf_app_data(ca, conn, conf_ref);

    if (fort_callout_ale_allowed(conn, conf_flags, app_data)) {

        if (fort_callout_ale_process_flow(ca, cx, conf_flags)) {
            conn->blocked = TRUE; /* block (Error | Pending) */
            return;
        }
    }

    fort_callout_ale_log_app_path(cx, conf_ref, conf_flags, app_data);
}

inline static BOOL fort_callout_ale_check_filter_lan_flags(
        PFORT_CONF_META_CONN conn, const FORT_CONF_FLAGS conf_flags)
{
    if (conf_flags.block_lan_traffic && !conn->is_loopback) {
        return TRUE; /* block LAN */
    }

    if (!conf_flags.filter_local_net) {
        conn->blocked = FALSE;
        return TRUE; /* allow Local Network */
    }

    return FALSE;
}

inline static BOOL fort_callout_ale_check_filter_inet_flags(
        PFORT_CONF_META_CONN conn, const FORT_CONF_FLAGS conf_flags)
{
    if (conf_flags.block_inet_traffic && !conn->is_broadcast) {
        return TRUE; /* block Internet */
    }

    return FALSE;
}

inline static BOOL fort_callout_ale_check_filter_net_flags(
        PFORT_CONF_META_CONN conn, const FORT_CONF_FLAGS conf_flags)
{
    if (conn->is_local_net) {
        return fort_callout_ale_check_filter_lan_flags(conn, conf_flags);
    } else {
        return fort_callout_ale_check_filter_inet_flags(conn, conf_flags);
    }
}

inline static BOOL fort_callout_ale_check_filter_flags(PCFORT_CALLOUT_ARG ca,
        PFORT_CONF_META_CONN conn, PFORT_CONF_REF conf_ref, const FORT_CONF_FLAGS conf_flags)
{
    if (conf_flags.block_traffic) {
        return TRUE; /* block all */
    }

    fort_callout_ale_fill_meta_conn(ca, conn);

    /* LAN addresses */
    {
        UCHAR local_zone_id;
        const FORT_CONF_ADDR_GROUP_IP_INCLUDED_OPT opt = {
            .zone_func = (fort_conf_zones_ip_included_func *) &fort_devconf_zones_ip_included,
            .ctx = &fort_device()->conf,
            .addr_group_index = 0, /* LAN */
            .zone_id = &local_zone_id,
        };
        conn->is_local_net = !fort_conf_addr_group_ip_included(&conf_ref->conf, conn, &opt);

        if (fort_callout_ale_check_filter_net_flags(conn, conf_flags)) {
            return TRUE; /* block net */
        }
    }

    /* INET addresses */
    {
        const FORT_CONF_ADDR_GROUP_IP_INCLUDED_OPT opt = {
            .zone_func = (fort_conf_zones_ip_included_func *) &fort_devconf_zones_ip_included,
            .ctx = &fort_device()->conf,
            .addr_group_index = 1, /* INET */
            .zone_id = &conn->zone_id,
        };

        if (!fort_conf_addr_group_ip_included(&conf_ref->conf, conn, &opt)) {
            conn->reason = FORT_CONN_REASON_IP_INET;
            return TRUE; /* block address */
        }
    }

    return FALSE;
}

inline static BOOL fort_callout_ale_check_flags(PCFORT_CALLOUT_ARG ca, PFORT_CONF_META_CONN conn,
        PFORT_CONF_REF conf_ref, const FORT_CONF_FLAGS conf_flags)
{
    if (conf_flags.filter_enabled) {
        return fort_callout_ale_check_filter_flags(ca, conn, conf_ref, conf_flags);
    }

    conn->blocked = FALSE;

    if (!(conf_flags.log_stat && conf_flags.log_stat_no_filter))
        return TRUE; /* allow (Filter Disabled) */

    return FALSE;
}

inline static void fort_callout_ale_classify_action(
        PCFORT_CALLOUT_ARG ca, PCFORT_CONF_META_CONN conn)
{
    FWPS_CLASSIFY_OUT0 *classifyOut = ca->classifyOut;

    if (conn->ignore) {
        /* Continue the search */
        fort_callout_classify_continue(classifyOut);
    } else if (conn->drop_blocked) {
        /* Drop the connection */
        fort_callout_classify_drop(classifyOut);
    } else if (conn->blocked) {
        /* Block the connection */
        fort_callout_classify_block(classifyOut);
    } else {
        /* Allow the connection */
        fort_callout_classify_permit(ca->filter, classifyOut);
    }
}

inline static void fort_callout_ale_classify_boot_action(
        PCFORT_CALLOUT_ARG ca, PFORT_DEVICE_CONF device_conf)
{
    FWPS_CLASSIFY_OUT0 *classifyOut = ca->classifyOut;

    const BOOL isBootFilter = fort_device_flag(device_conf, FORT_DEVICE_BOOT_FILTER) != 0;
    if (isBootFilter) {
        /* Block the connection */
        fort_callout_classify_block(classifyOut);
    } else {
        /* Continue the search */
        fort_callout_classify_continue(classifyOut);
    }
}

inline static void fort_callout_ale_check_conf(PCFORT_CALLOUT_ARG ca, PFORT_CALLOUT_ALE_EXTRA cx,
        PFORT_CONF_REF conf_ref, const FORT_CONF_FLAGS conf_flags)
{
    PFORT_CONF_META_CONN conn = &cx->conn;

    fort_callout_ale_fill_meta_conn_proc(ca, conn);

    conn->blocked = TRUE;
    conn->reason = FORT_CONN_REASON_UNKNOWN;

    if (!fort_callout_ale_check_flags(ca, conn, conf_ref, conf_flags)) {
        fort_callout_ale_fill_meta_conn(ca, conn);

        fort_callout_ale_check_app(ca, cx, conf_ref, conf_flags);
    }

    /* Log the connection */
    if (fort_callout_ale_log_conn_check(ca, conn, conf_ref, conf_flags)) {
        fort_callout_ale_fill_meta_conn(ca, conn);

        fort_buffer_conn_write(
                &fort_device()->buffer, conn, &cx->irp_info, FORT_BUFFER_CONN_WRITE_CONN);
    }

    fort_callout_ale_classify_action(ca, conn);

    /* Free the allocated path */
    fort_path_buffer_free(&conn->path_buf);
}

inline static void fort_callout_ale_by_conf(PCFORT_CALLOUT_ARG ca, PFORT_CALLOUT_ALE_EXTRA cx,
        PFORT_DEVICE_CONF device_conf, const FORT_CONF_FLAGS conf_flags)
{
    const BOOL ps_enumerated = fort_device_flag(device_conf, FORT_DEVICE_PS_ENUMERATED) != 0;

    PFORT_CONF_REF conf_ref = ps_enumerated ? fort_conf_ref_take(device_conf) : NULL;

    if (conf_ref == NULL) {
        fort_callout_ale_classify_boot_action(ca, device_conf);
        return;
    }

    PFORT_IRP_INFO irp_info = &cx->irp_info;
    irp_info->irp = NULL;

    fort_callout_ale_check_conf(ca, cx, conf_ref, conf_flags);

    fort_conf_ref_put(device_conf, conf_ref);

    if (irp_info->irp != NULL) {
        fort_buffer_irp_clear_pending(irp_info);
        fort_request_complete_info(irp_info, STATUS_SUCCESS);
    }
}

inline static BOOL fort_addr_is_local_broadcast(PCFORT_CONF_META_CONN conn)
{
    if (conn->isIPv6) {
        return conn->remote_ip.v2 == 0x2FF;
    }

    return conn->remote_ip.v4 == 0xFFFFFFFF;
}

inline static BOOL fort_callout_ale_is_local_address(
        PFORT_CALLOUT_ARG ca, PFORT_CALLOUT_ALE_EXTRA cx, const FORT_CONF_FLAGS conf_flags)
{
    PFORT_CONF_META_CONN conn = &cx->conn;

    fort_callout_fill_meta_ip(ca, ca->fi->remoteIp, &conn->remote_ip);

    conn->is_broadcast = (UINT16) fort_addr_is_local_broadcast(conn);

    if (conf_flags.filter_locals)
        return FALSE;

    /* Loopback */
    if (conn->is_loopback) {
        return !conf_flags.block_traffic;
    }

    /* Broadcast */
    if (conn->is_broadcast) {
        return !conf_flags.block_lan_traffic;
    }

    return FALSE;
}

static void fort_callout_ale_classify(PFORT_CALLOUT_ARG ca)
{
    FORT_CHECK_STACK(FORT_CALLOUT_ALE_CLASSIFY);

    const UINT32 classify_flags = ca->inFixedValues->incomingValue[ca->fi->flags].value.uint32;

    FORT_CALLOUT_ALE_EXTRA cx = {
        .conn = {
            .inbound = ca->inbound,
            .isIPv6 = ca->isIPv6,
            .is_loopback = (classify_flags & FWP_CONDITION_FLAG_IS_LOOPBACK) != 0,
            .is_reauth = (classify_flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0,
        },
    };

    PFORT_DEVICE_CONF device_conf = &fort_device()->conf;
    const FORT_CONF_FLAGS conf_flags = device_conf->conf_flags;

    if (fort_callout_ale_is_local_address(ca, &cx, conf_flags)) {
        fort_callout_classify_permit(ca->filter, ca->classifyOut);
        return;
    }

    fort_callout_ale_by_conf(ca, &cx, device_conf, conf_flags);
}

inline static void fort_callout_ale_classify_v(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PVOID layerData,
        const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut,
        PCFORT_CALLOUT_FIELD_INDEX fi, BOOL inbound, BOOL isIPv6)
{
    FORT_CALLOUT_ARG ca = {
        .fi = fi,
        .inFixedValues = inFixedValues,
        .inMetaValues = inMetaValues,
        .netBufList = layerData,
        .filter = filter,
        .classifyOut = classifyOut,
        .flowContext = flowContext,
        .inbound = inbound,
        .isIPv6 = isIPv6,
    };

    fort_callout_ale_classify(&ca);
}

static void NTAPI fort_callout_connect_v4(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PVOID layerData,
        const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    static const FORT_CALLOUT_FIELD_INDEX fi = {
        .flags = FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS,
        .localIp = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS,
        .remoteIp = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
        .localPort = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT,
        .remotePort = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT,
        .ipProto = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL,
        .profileId = FWPS_FIELD_ALE_AUTH_CONNECT_V4_ORIGINAL_PROFILE_ID,
    };

    fort_callout_ale_classify_v(inFixedValues, inMetaValues, layerData, filter, flowContext,
            classifyOut, &fi, /*inbound=*/FALSE, /*isIPv6=*/FALSE);
}

static void NTAPI fort_callout_connect_v6(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PVOID layerData,
        const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    static const FORT_CALLOUT_FIELD_INDEX fi = {
        .flags = FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS,
        .localIp = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS,
        .remoteIp = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS,
        .localPort = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT,
        .remotePort = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT,
        .ipProto = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL,
        .profileId = FWPS_FIELD_ALE_AUTH_CONNECT_V6_ORIGINAL_PROFILE_ID,
    };

    fort_callout_ale_classify_v(inFixedValues, inMetaValues, layerData, filter, flowContext,
            classifyOut, &fi, /*inbound=*/FALSE, /*isIPv6=*/TRUE);
}

/*
 * Force an application/rule to egress via a specific network interface.
 *
 * The UI resolves the configured NET_LUID to the interface's local IPv4/IPv6
 * address and stores it in the conf's interface table. Here, at the
 * ALE_CONNECT_REDIRECT layer, the connection's local (source) address is
 * rewritten to that interface's address, forcing the OS to route the
 * connection out through that interface.
 *
 * Precedence: the application's forced interface wins; a rule's forced
 * interface is used only when the application defines none.
 *
 * When a forced interface is configured but currently unavailable (no IP for
 * the connection's address family), the connection is blocked until the
 * interface comes back (the UI re-pushes the conf on network changes).
 */
static PCFORT_CONF_IFACE fort_callout_redirect_iface(
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PFORT_CONF_REF conf_ref, BOOL isIPv6,
        BOOL *out_block)
{
    PFORT_DEVICE_CONF device_conf = &fort_device()->conf;

    FORT_CALLOUT_ALE_EXTRA cx = { 0 };
    PFORT_CONF_META_CONN conn = &cx.conn;

    FORT_CALLOUT_ARG ca = {
        .inMetaValues = inMetaValues,
        .isIPv6 = (UCHAR) isIPv6,
    };

    conn->process_id = (UINT32) inMetaValues->processId;

    fort_callout_ale_fill_meta_path(&ca, conn);

    const FORT_APP_DATA app_data =
            fort_conf_app_find(&conf_ref->conf, &conn->path, fort_conf_exe_find, conf_ref);

    /* Precedence: app first, then rules (app rule, then global pre/post) */
    UCHAR iface_index = app_data.flags.found ? app_data.iface_index : 0;

    if (iface_index == 0) {
        iface_index = fort_devconf_rule_iface_index(device_conf, app_data.rule_id);

        if (iface_index == 0) {
            const FORT_CONF_RULES_GLOB glob = device_conf->rules_glob;

            iface_index = fort_devconf_rule_iface_index(device_conf, glob.pre_rule_id);
            if (iface_index == 0) {
                iface_index = fort_devconf_rule_iface_index(device_conf, glob.post_rule_id);
            }
        }
    }

    fort_path_buffer_free(&conn->path_buf);

    if (iface_index == 0)
        return NULL; /* no forced interface */

    PCFORT_CONF_IFACE iface = fort_conf_iface_ref(&conf_ref->conf, iface_index);

    const UINT16 need = (UINT16) (isIPv6 ? FORT_CONF_IFACE_HAS_IP6 : FORT_CONF_IFACE_HAS_IP4);

    if (iface == NULL || (iface->flags & need) == 0) {
        *out_block = TRUE; /* forced but unavailable */
        return NULL;
    }

    return iface;
}

static void fort_callout_redirect_apply(const void *classifyContext, const FWPS_FILTER3 *filter,
        FWPS_CLASSIFY_OUT0 *classifyOut, PCFORT_CONF_IFACE iface, BOOL isIPv6)
{
    UINT64 classifyHandle = 0;
    NTSTATUS status = FwpsAcquireClassifyHandle0((void *) classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status))
        return;

    FWPS_CONNECT_REQUEST0 *request = NULL;
    status = FwpsAcquireWritableLayerDataPointer0(
            classifyHandle, filter->filterId, 0, (PVOID *) &request, classifyOut);
    if (!NT_SUCCESS(status)) {
        FwpsReleaseClassifyHandle0(classifyHandle);
        return;
    }

    /* Loop guard: do not re-redirect a connection we already redirected */
    if (request->localRedirectHandle != g_redirectGlobal.redirect_handle) {
        if (isIPv6) {
            SOCKADDR_IN6 *sin6 = (SOCKADDR_IN6 *) &request->localAddressAndPort;
            sin6->sin6_family = AF_INET6;
            RtlCopyMemory(&sin6->sin6_addr, iface->ip6.data, sizeof(ip6_addr_t));
        } else {
            SOCKADDR_IN *sin = (SOCKADDR_IN *) &request->localAddressAndPort;
            sin->sin_family = AF_INET;
            sin->sin_addr.s_addr = iface->ip4; /* network byte order */
        }

        request->localRedirectHandle = g_redirectGlobal.redirect_handle;
    }

    FwpsApplyModifiedLayerData0(classifyHandle, request, 0);
    FwpsReleaseClassifyHandle0(classifyHandle);
}

static void fort_callout_redirect_classify(const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
        const void *classifyContext, const FWPS_FILTER3 *filter, FWPS_CLASSIFY_OUT0 *classifyOut,
        BOOL isIPv6)
{
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
        return; /* can not modify */

    PFORT_DEVICE_CONF device_conf = &fort_device()->conf;

    if (fort_device_flag(device_conf, FORT_DEVICE_PS_ENUMERATED) == 0)
        return;

    PFORT_CONF_REF conf_ref = fort_conf_ref_take(device_conf);
    if (conf_ref == NULL)
        return;

    BOOL do_block = FALSE;
    PCFORT_CONF_IFACE iface =
            fort_callout_redirect_iface(inMetaValues, conf_ref, isIPv6, &do_block);

    FORT_CONF_IFACE iface_copy = { 0 };
    const BOOL do_redirect = (iface != NULL);
    if (do_redirect) {
        iface_copy = *iface; /* copy before releasing conf_ref */
    }

    fort_conf_ref_put(device_conf, conf_ref);

    if (do_block) {
        fort_callout_classify_block(classifyOut);
        return;
    }

    if (!do_redirect)
        return; /* no forced interface: leave the connection unchanged */

    fort_callout_redirect_apply(classifyContext, filter, classifyOut, &iface_copy, isIPv6);
}

static void NTAPI fort_callout_connect_redirect_v4(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, void *layerData,
        const void *classifyContext, const FWPS_FILTER3 *filter, UINT64 flowContext,
        FWPS_CLASSIFY_OUT0 *classifyOut)
{
    UNUSED(inFixedValues);
    UNUSED(layerData);
    UNUSED(flowContext);

    fort_callout_redirect_classify(
            inMetaValues, classifyContext, filter, classifyOut, /*isIPv6=*/FALSE);
}

static void NTAPI fort_callout_connect_redirect_v6(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, void *layerData,
        const void *classifyContext, const FWPS_FILTER3 *filter, UINT64 flowContext,
        FWPS_CLASSIFY_OUT0 *classifyOut)
{
    UNUSED(inFixedValues);
    UNUSED(layerData);
    UNUSED(flowContext);

    fort_callout_redirect_classify(
            inMetaValues, classifyContext, filter, classifyOut, /*isIPv6=*/TRUE);
}

static NTSTATUS NTAPI fort_callout_redirect_notify(
        FWPS_CALLOUT_NOTIFY_TYPE notifyType, const GUID *filterKey, FWPS_FILTER3 *filter)
{
    UNUSED(notifyType);
    UNUSED(filterKey);
    UNUSED(filter);

    return STATUS_SUCCESS;
}

static void NTAPI fort_callout_accept_v4(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PVOID layerData,
        const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    static const FORT_CALLOUT_FIELD_INDEX fi = {
        .flags = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS,
        .localIp = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS,
        .remoteIp = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS,
        .localPort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT,
        .remotePort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT,
        .ipProto = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL,
        .profileId = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_ORIGINAL_PROFILE_ID,
    };

    fort_callout_ale_classify_v(inFixedValues, inMetaValues, layerData, filter, flowContext,
            classifyOut, &fi, /*inbound=*/TRUE, /*isIPv6=*/FALSE);
}

static void NTAPI fort_callout_accept_v6(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PVOID layerData,
        const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    static const FORT_CALLOUT_FIELD_INDEX fi = {
        .flags = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS,
        .localIp = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS,
        .remoteIp = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS,
        .localPort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT,
        .remotePort = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT,
        .ipProto = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL,
        .profileId = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_ORIGINAL_PROFILE_ID,
    };

    fort_callout_ale_classify_v(inFixedValues, inMetaValues, layerData, filter, flowContext,
            classifyOut, &fi, /*inbound=*/TRUE, /*isIPv6=*/TRUE);
}

static NTSTATUS NTAPI fort_callout_notify(
        FWPS_CALLOUT_NOTIFY_TYPE notifyType, const GUID *filterKey, FWPS_FILTER0 *filter)
{
    UNUSED(notifyType);
    UNUSED(filterKey);
    UNUSED(filter);

    return STATUS_SUCCESS;
}

inline static UINT32 fort_packet_data_size(const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues,
        const PNET_BUFFER_LIST netBufList, BOOL inbound)
{
    if (netBufList == NULL)
        return 0;

    PNET_BUFFER netBuf = NET_BUFFER_LIST_FIRST_NB(netBufList);
    const UINT32 dataSize = NET_BUFFER_DATA_LENGTH(netBuf);

    const UINT32 headerSize =
            inbound ? inMetaValues->ipHeaderSize + inMetaValues->transportHeaderSize : 0;

    return dataSize + headerSize;
}

inline static BOOL fort_callout_transport_classify_packet_blocked(FWPS_CLASSIFY_OUT0 *classifyOut)
{
    if (classifyOut->actionType == FWP_ACTION_BLOCK) {
        fort_callout_classify_continue(classifyOut); /* continue */
        return TRUE;
    }

    return FALSE;
}

inline static BOOL fort_callout_transport_classify_packet(
        FWPS_CLASSIFY_OUT0 *classifyOut, PFORT_CALLOUT_ARG ca)
{
    if ((classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        /* Can't act on the packet */
        return fort_callout_transport_classify_packet_blocked(classifyOut);
    }

    if (fort_shaper_packet_process(&fort_device()->shaper, ca)) {
        fort_callout_classify_drop(classifyOut); /* drop */
        return TRUE;
    }

    return FALSE;
}

static void fort_callout_transport_classify(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PVOID layerData,
        const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut,
        BOOL inbound)
{
    FORT_CHECK_STACK(FORT_CALLOUT_TRANSPORT_CLASSIFY);

    const PNET_BUFFER_LIST netBufList = layerData;

    FORT_CALLOUT_ARG ca = {
        .inFixedValues = inFixedValues,
        .inMetaValues = inMetaValues,
        .netBufList = netBufList,
        .filter = filter,
        .classifyOut = classifyOut,
        .flowContext = flowContext,
        .dataSize = fort_packet_data_size(inMetaValues, netBufList, inbound),
        .inbound = inbound,
    };

    if (fort_callout_transport_classify_packet(classifyOut, &ca))
        return;

    fort_flow_classify(&fort_device()->stat, flowContext, ca.dataSize, inbound);

    fort_callout_classify_continue(classifyOut); /* continue */
}

static void NTAPI fort_callout_transport_classify_in(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PVOID layerData,
        const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    fort_callout_transport_classify(inFixedValues, inMetaValues, layerData, filter, flowContext,
            classifyOut, /*inbound=*/TRUE);
}

static void NTAPI fort_callout_transport_classify_out(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PVOID layerData,
        const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    fort_callout_transport_classify(inFixedValues, inMetaValues, layerData, filter, flowContext,
            classifyOut, /*inbound=*/FALSE);
}

static void NTAPI fort_callout_flow_delete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
    UNUSED(layerId);
    UNUSED(calloutId);

    FORT_CHECK_STACK(FORT_CALLOUT_FLOW_DELETE);

    fort_shaper_drop_flow_packets(&fort_device()->shaper, flowContext);

    fort_flow_delete(&fort_device()->stat, flowContext);
}

static void fort_callout_discard_classify(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PVOID layerData,
        const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut,
        UCHAR flagsIndex)
{
    UNUSED(inMetaValues);
    UNUSED(layerData);
    UNUSED(flowContext);

    FORT_CHECK_STACK(FORT_CALLOUT_DISCARD_CLASSIFY);

    const UINT32 classify_flags = inFixedValues->incomingValue[flagsIndex].value.uint32;
    const BOOL is_loopback = (classify_flags & FWP_CONDITION_FLAG_IS_LOOPBACK) != 0;

    if (is_loopback) {
        fort_callout_classify_permit(filter, classifyOut); /* permit */
    } else {
        fort_callout_classify_block(classifyOut); /* block */
    }
}

static void NTAPI fort_callout_transport_discard_in_v4(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PVOID layerData,
        const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    fort_callout_discard_classify(inFixedValues, inMetaValues, layerData, filter, flowContext,
            classifyOut, FWPS_FIELD_INBOUND_TRANSPORT_V4_FLAGS);
}

static void NTAPI fort_callout_transport_discard_in_v6(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PVOID layerData,
        const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    fort_callout_discard_classify(inFixedValues, inMetaValues, layerData, filter, flowContext,
            classifyOut, FWPS_FIELD_INBOUND_TRANSPORT_V6_FLAGS);
}

static void NTAPI fort_callout_ippacket_discard_in_v4(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PVOID layerData,
        const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    fort_callout_discard_classify(inFixedValues, inMetaValues, layerData, filter, flowContext,
            classifyOut, FWPS_FIELD_INBOUND_IPPACKET_V4_FLAGS);
}

static void NTAPI fort_callout_ippacket_discard_in_v6(const FWPS_INCOMING_VALUES0 *inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0 *inMetaValues, PVOID layerData,
        const FWPS_FILTER0 *filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0 *classifyOut)
{
    fort_callout_discard_classify(inFixedValues, inMetaValues, layerData, filter, flowContext,
            classifyOut, FWPS_FIELD_INBOUND_IPPACKET_V6_FLAGS);
}

static void NTAPI fort_callout_delete(UINT16 layerId, UINT32 calloutId, UINT64 flowContext)
{
    UNUSED(layerId);
    UNUSED(calloutId);
    UNUSED(flowContext);
}

static void fort_callout_init_callout(FWPS_CALLOUT0 *cout, GUID calloutKey,
        FWPS_CALLOUT_CLASSIFY_FN0 classifyFn, FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 flowDeleteFn,
        UINT32 flags)
{
    cout->calloutKey = calloutKey;
    cout->flags = flags;
    cout->classifyFn = classifyFn;
    cout->notifyFn = &fort_callout_notify;
    cout->flowDeleteFn = flowDeleteFn;
}

inline static void fort_callout_init_ale_callout(
        FWPS_CALLOUT0 *cout, GUID calloutKey, FWPS_CALLOUT_CLASSIFY_FN0 classifyFn)
{
    fort_callout_init_callout(cout, calloutKey, classifyFn,
            /*flowDeleteFn=*/NULL, /*flags=*/0);
}

static void fort_callout_init_ale_callouts(void)
{
    FWPS_CALLOUT0 *cout = g_calloutGlobal.ale_callouts;

    /* IPv4 connect callout */
    fort_callout_init_ale_callout(cout++, FORT_GUID_CALLOUT_CONNECT_V4, &fort_callout_connect_v4);
    /* IPv6 connect callout */
    fort_callout_init_ale_callout(cout++, FORT_GUID_CALLOUT_CONNECT_V6, &fort_callout_connect_v6);
    /* IPv4 accept callout */
    fort_callout_init_ale_callout(cout++, FORT_GUID_CALLOUT_ACCEPT_V4, &fort_callout_accept_v4);
    /* IPv6 accept callout */
    fort_callout_init_ale_callout(cout++, FORT_GUID_CALLOUT_ACCEPT_V6, &fort_callout_accept_v6);
}

inline static void fort_callout_init_packet_callout(FWPS_CALLOUT0 *cout, GUID calloutKey,
        FWPS_CALLOUT_CLASSIFY_FN0 classifyFn, FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN0 flowDeleteFn)
{
    fort_callout_init_callout(
            cout, calloutKey, classifyFn, flowDeleteFn, FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW);
}

static void fort_callout_init_packet_callouts(void)
{
    FWPS_CALLOUT0 *cout = g_calloutGlobal.packet_callouts;

    /* IPv4 inbound transport callout */
    fort_callout_init_packet_callout(cout++, FORT_GUID_CALLOUT_IN_TRANSPORT_V4,
            &fort_callout_transport_classify_in, &fort_callout_flow_delete);
    /* IPv6 inbound transport callout */
    fort_callout_init_packet_callout(cout++, FORT_GUID_CALLOUT_IN_TRANSPORT_V6,
            &fort_callout_transport_classify_in, &fort_callout_flow_delete);
    /* IPv4 outbound transport callout */
    fort_callout_init_packet_callout(cout++, FORT_GUID_CALLOUT_OUT_TRANSPORT_V4,
            &fort_callout_transport_classify_out, &fort_callout_delete);
    /* IPv6 outbound transport callout */
    fort_callout_init_packet_callout(cout++, FORT_GUID_CALLOUT_OUT_TRANSPORT_V6,
            &fort_callout_transport_classify_out, &fort_callout_delete);
}

inline static void fort_callout_init_discard_callout(
        FWPS_CALLOUT0 *cout, GUID calloutKey, FWPS_CALLOUT_CLASSIFY_FN0 classifyFn)
{
    fort_callout_init_callout(cout, calloutKey, classifyFn,
            /*flowDeleteFn=*/NULL, /*flags=*/0);
}

static void fort_callout_init_discard_callouts(void)
{
    FWPS_CALLOUT0 *cout = g_calloutGlobal.discard_callouts;

    /* IPv4 inbound transport discard callout */
    fort_callout_init_discard_callout(cout++, FORT_GUID_CALLOUT_IN_TRANSPORT_DISCARD_V4,
            &fort_callout_transport_discard_in_v4);
    /* IPv6 inbound transport discard callout */
    fort_callout_init_discard_callout(cout++, FORT_GUID_CALLOUT_IN_TRANSPORT_DISCARD_V6,
            &fort_callout_transport_discard_in_v6);
    /* IPv4 inbound ippacket discard callout */
    fort_callout_init_discard_callout(
            cout++, FORT_GUID_CALLOUT_IN_IPPACKET_DISCARD_V4, &fort_callout_ippacket_discard_in_v4);
    /* IPv6 inbound ippacket discard callout */
    fort_callout_init_discard_callout(
            cout++, FORT_GUID_CALLOUT_IN_IPPACKET_DISCARD_V6, &fort_callout_ippacket_discard_in_v6);
}

static void fort_callout_init_redirect_callouts(void)
{
    FWPS_CALLOUT3 *cout = g_redirectGlobal.callouts;

    /* IPv4 connect redirect callout */
    cout[0].calloutKey = FORT_GUID_CALLOUT_CONNECT_REDIRECT_V4;
    cout[0].flags = 0;
    cout[0].classifyFn = &fort_callout_connect_redirect_v4;
    cout[0].notifyFn = &fort_callout_redirect_notify;
    cout[0].flowDeleteFn = NULL;

    /* IPv6 connect redirect callout */
    cout[1].calloutKey = FORT_GUID_CALLOUT_CONNECT_REDIRECT_V6;
    cout[1].flags = 0;
    cout[1].classifyFn = &fort_callout_connect_redirect_v6;
    cout[1].notifyFn = &fort_callout_redirect_notify;
    cout[1].flowDeleteFn = NULL;
}

static void fort_callout_init(void)
{
    RtlZeroMemory(&g_calloutGlobal, sizeof(g_calloutGlobal));
    RtlZeroMemory(&g_redirectGlobal, sizeof(g_redirectGlobal));

    fort_callout_init_ale_callouts();
    fort_callout_init_packet_callouts();
    fort_callout_init_discard_callouts();
    fort_callout_init_redirect_callouts();
}

static NTSTATUS fort_callout_register(
        PDEVICE_OBJECT device, const FWPS_CALLOUT0 *callouts, const PUINT32 calloutIds, int count)
{
    for (int i = 0; i < count; ++i) {
        const NTSTATUS status = FwpsCalloutRegister0(device, &callouts[i], &calloutIds[i]);
        if (!NT_SUCCESS(status)) {
            LOG("Callout Register: Error: %x\n", status);
            TRACE(FORT_CALLOUT_REGISTER_ERROR, status, i, 0);
            return status;
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS fort_callout_install_ale(PDEVICE_OBJECT device, PFORT_STAT stat)
{
    const PUINT32 calloutIds = &stat->callout_ids[FORT_STAT_ALE_CALLOUT_IDS_INDEX];

    return fort_callout_register(
            device, g_calloutGlobal.ale_callouts, calloutIds, FORT_STAT_ALE_CALLOUT_IDS_COUNT);
}

static NTSTATUS fort_callout_install_packet(PDEVICE_OBJECT device, PFORT_STAT stat)
{
    const PUINT32 calloutIds = &stat->callout_ids[FORT_STAT_PACKET_CALLOUT_IDS_INDEX];

    return fort_callout_register(device, g_calloutGlobal.packet_callouts, calloutIds,
            FORT_STAT_PACKET_CALLOUT_IDS_COUNT);
}

static NTSTATUS fort_callout_install_discard(PDEVICE_OBJECT device, PFORT_STAT stat)
{
    const PUINT32 calloutIds = &stat->callout_ids[FORT_STAT_DISCARD_CALLOUT_IDS_INDEX];

    return fort_callout_register(device, g_calloutGlobal.discard_callouts, calloutIds,
            FORT_STAT_DISCARD_CALLOUT_IDS_COUNT);
}

static NTSTATUS fort_callout_install_redirect(PDEVICE_OBJECT device)
{
    NTSTATUS status;

    status = FwpsRedirectHandleCreate0(
            &FORT_GUID_PROVIDER, 0, &g_redirectGlobal.redirect_handle);
    if (!NT_SUCCESS(status)) {
        LOG("Callout Redirect: Create handle error: %x\n", status);
        TRACE(FORT_CALLOUT_REGISTER_ERROR, status, 0, 0);
        return status;
    }

    for (int i = 0; i < FORT_REDIRECT_CALLOUTS_COUNT; ++i) {
        status = FwpsCalloutRegister3(
                device, &g_redirectGlobal.callouts[i], &g_redirectGlobal.callout_ids[i]);
        if (!NT_SUCCESS(status)) {
            LOG("Callout Redirect: Register error: %x\n", status);
            TRACE(FORT_CALLOUT_REGISTER_ERROR, status, i, 0);
            return status;
        }
    }

    return STATUS_SUCCESS;
}

FORT_API NTSTATUS fort_callout_install(PDEVICE_OBJECT device)
{
    FORT_CHECK_STACK(FORT_CALLOUT_INSTALL);

    PFORT_STAT stat = &fort_device()->stat;

    fort_callout_init();

    NTSTATUS status;

    if (!NT_SUCCESS(status = fort_callout_install_ale(device, stat)))
        return status;

    if (!NT_SUCCESS(status = fort_callout_install_packet(device, stat)))
        return status;

    if (!NT_SUCCESS(status = fort_callout_install_discard(device, stat)))
        return status;

    if (!NT_SUCCESS(status = fort_callout_install_redirect(device)))
        return status;

    return STATUS_SUCCESS;
}

FORT_API void fort_callout_remove(void)
{
    FORT_CHECK_STACK(FORT_CALLOUT_REMOVE);

    PFORT_STAT stat = &fort_device()->stat;

    const PUINT32 calloutIds = stat->callout_ids;

    for (int i = 0; i < FORT_STAT_CALLOUT_IDS_COUNT; ++i) {
        PUINT32 calloutId = &calloutIds[i];
        FwpsCalloutUnregisterById0(*calloutId);
        *calloutId = 0;
    }

    for (int i = 0; i < FORT_REDIRECT_CALLOUTS_COUNT; ++i) {
        if (g_redirectGlobal.callout_ids[i] != 0) {
            FwpsCalloutUnregisterById0(g_redirectGlobal.callout_ids[i]);
            g_redirectGlobal.callout_ids[i] = 0;
        }
    }

    if (g_redirectGlobal.redirect_handle != NULL) {
        FwpsRedirectHandleDestroy0(g_redirectGlobal.redirect_handle);
        g_redirectGlobal.redirect_handle = NULL;
    }
}

inline static NTSTATUS fort_callout_force_reauth_prov_flow_filters(HANDLE engine,
        const FORT_CONF_FLAGS old_conf_flags, const FORT_CONF_FLAGS conf_flags, BOOL force)
{
    const BOOL conf_changed = (old_conf_flags.log_stat != conf_flags.log_stat);

    if (!force && !conf_changed)
        return STATUS_SUCCESS;

    fort_prov_flow_unregister(engine);

    if (!conf_flags.log_stat)
        return STATUS_SUCCESS;

    return fort_prov_flow_register(engine);
}

inline static NTSTATUS fort_callout_force_reauth_prov_recreate(HANDLE engine,
        const FORT_CONF_FLAGS old_conf_flags, const FORT_CONF_FLAGS conf_flags,
        BOOL *prov_recreated)
{
    const BOOL conf_changed = (old_conf_flags.boot_filter != conf_flags.boot_filter
            || old_conf_flags.stealth_mode != conf_flags.stealth_mode
            || old_conf_flags.filter_locals != conf_flags.filter_locals);

    if (!conf_changed)
        return STATUS_SUCCESS;

    const FORT_PROV_BOOT_CONF boot_conf = {
        .boot_filter = conf_flags.boot_filter,
        .filter_locals = conf_flags.filter_locals,
        .stealth_mode = conf_flags.stealth_mode,
    };

    fort_prov_unregister(engine);

    const NTSTATUS status = fort_prov_register(engine, boot_conf);
    if (status == 0) {
        *prov_recreated = TRUE;
    }

    return status;
}

inline static NTSTATUS fort_callout_force_reauth_prov_filters(
        HANDLE engine, const FORT_CONF_FLAGS old_conf_flags, const FORT_CONF_FLAGS conf_flags)
{
    NTSTATUS status;

    /* Check provider filters */
    BOOL prov_recreated = FALSE;
    status = fort_callout_force_reauth_prov_recreate(
            engine, old_conf_flags, conf_flags, &prov_recreated);
    if (status != 0)
        return status;

    /* Check flow filter */
    status = fort_callout_force_reauth_prov_flow_filters(engine, old_conf_flags, conf_flags,
            /*force=*/prov_recreated);
    if (status != 0)
        return status;

    /* Force reauth filter */
    fort_prov_reauth(engine);

    return STATUS_SUCCESS;
}

inline static NTSTATUS fort_callout_force_reauth_prov(
        const FORT_CONF_FLAGS old_conf_flags, const FORT_CONF_FLAGS conf_flags)
{
    NTSTATUS status;

    HANDLE engine;
    status = fort_prov_trans_open(&engine);
    if (!NT_SUCCESS(status))
        return status;

    status = fort_callout_force_reauth_prov_filters(engine, old_conf_flags, conf_flags);

    return fort_prov_trans_close(engine, status);
}

FORT_API NTSTATUS fort_callout_force_reauth(const FORT_CONF_FLAGS old_conf_flags)
{
    FORT_CHECK_STACK(FORT_CALLOUT_FORCE_REAUTH);

    NTSTATUS status;

    const FORT_CONF_FLAGS conf_flags = fort_device()->conf.conf_flags;

    /* Handle log_stat */
    fort_stat_log_update(&fort_device()->stat, conf_flags.log_stat);

    /* Run the log_timer */
    fort_timer_set_running(&fort_device()->log_timer, /*run=*/conf_flags.log_stat);

    /* Reauth provider filters */
    status = fort_callout_force_reauth_prov(old_conf_flags, conf_flags);

    if (!NT_SUCCESS(status)) {
        LOG("Callout Reauth: Error: %x\n", status);
        TRACE(FORT_CALLOUT_CALLOUT_REAUTH_ERROR, status, 0, 0);
    }

    return status;
}

inline static void fort_callout_update_system_time(
        PFORT_STAT stat, PFORT_BUFFER buf, PFORT_IRP_INFO irp_info)
{
    LARGE_INTEGER system_time;
    KeQuerySystemTime(&system_time);

    if (stat->system_time.QuadPart == system_time.QuadPart)
        return;

    stat->system_time = system_time;

    const INT64 unix_time = fort_system_to_unix_time(system_time.QuadPart);

    const UCHAR old_stat_flags = fort_stat_flags_set(stat, FORT_STAT_SYSTEM_TIME_CHANGED, FALSE);
    const BOOL system_time_changed = (old_stat_flags & FORT_STAT_SYSTEM_TIME_CHANGED) != 0;

    fort_buffer_system_time_write_locked(buf, irp_info, unix_time, system_time_changed);
}

inline static void fort_callout_flush_stat_traf(
        PFORT_STAT stat, PFORT_BUFFER buf, PFORT_IRP_INFO irp_info)
{
    while (stat->proc_active_count != 0) {
        const UINT16 proc_count = (stat->proc_active_count < FORT_LOG_STAT_BUFFER_PROC_COUNT)
                ? stat->proc_active_count
                : FORT_LOG_STAT_BUFFER_PROC_COUNT;
        const UINT32 len = FORT_LOG_STAT_SIZE(proc_count);
        PCHAR out;

        const NTSTATUS status = fort_buffer_prepare(buf, len, &out, irp_info);
        if (!NT_SUCCESS(status)) {
            LOG("Callout Timer: Error: %x\n", status);
            TRACE(FORT_CALLOUT_CALLOUT_TIMER_ERROR, status, 0, 0);
            break;
        }

        fort_log_stat_traf_header_write(out, proc_count);
        out += FORT_LOG_STAT_HEADER_SIZE;

        fort_stat_traf_flush(stat, proc_count, out);
    }
}

FORT_API void fort_callout_timer(void)
{
    FORT_CHECK_STACK(FORT_CALLOUT_TIMER);

    PFORT_BUFFER buf = &fort_device()->buffer;
    PFORT_STAT stat = &fort_device()->stat;

    FORT_IRP_INFO irp_info = { .irp = NULL };

    /* Lock buffer */
    KLOCK_QUEUE_HANDLE buf_lock_queue;
    fort_buffer_dpc_begin(buf, &buf_lock_queue);

    /* Lock stat */
    KLOCK_QUEUE_HANDLE stat_lock_queue;
    fort_stat_dpc_begin(stat, &stat_lock_queue);

    /* Get current Unix time */
    fort_callout_update_system_time(stat, buf, &irp_info);

    /* Flush traffic statistics */
    fort_callout_flush_stat_traf(stat, buf, &irp_info);

    /* Unlock stat */
    fort_stat_dpc_end(&stat_lock_queue);

    /* Flush pending buffer */
    if (irp_info.irp == NULL) {
        fort_buffer_flush_pending(buf, &irp_info);
    }

    /* Unlock buffer */
    fort_buffer_dpc_end(&buf_lock_queue);

    if (irp_info.irp != NULL) {
        fort_buffer_irp_clear_pending(&irp_info);
        fort_request_complete_info(&irp_info, STATUS_SUCCESS);
    }
}
