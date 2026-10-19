#!/bin/sh

## 循环更新脚本

. /usr/share/passwall/utils.sh
LOCK_FILE=${LOCK_PATH}/${CONFIG}_tasks.lock

CFG_UPDATE_INT=0

exec 99>"$LOCK_FILE"
flock -n 99 || exit 0

while true
do

	if [ "$CFG_UPDATE_INT" -ne 0 ]; then

		restart_week_mode=$(config_n_get @global_delay[0] restart_week_mode)
		restart_interval_mode=$(config_n_get @global_delay[0] restart_interval_mode)
		restart_interval_mode=$(expr "$restart_interval_mode" \* 60)
		if [ -n "$restart_week_mode" ]; then
			[ "$restart_week_mode" = "8" ] && {
				[ "$(expr "$CFG_UPDATE_INT" % "$restart_interval_mode")" -eq 0 ] && { /etc/init.d/$CONFIG restart cron > /dev/null 2>&1 99>&- & }
			}
		fi

		rules_update_week_mode=$(config_n_get @global_rules[0] update_week_mode)
		rules_update_interval_mode=$(config_n_get @global_rules[0] update_interval_mode)
		rules_update_interval_mode=$(expr "$rules_update_interval_mode" \* 60)
		if [ -n "$rules_update_week_mode" ]; then
			[ "$rules_update_week_mode" = "8" ] && {
				[ "$(expr "$CFG_UPDATE_INT" % "$rules_update_interval_mode")" -eq 0 ] && { lua "$APP_PATH/rule_update.lua" log all cron > /dev/null 2>&1 99>&- & }
			}
		fi


	fi

	CFG_UPDATE_INT=$(expr "$CFG_UPDATE_INT" + 10)

	sleep 600 99>&-

done 2>/dev/null
