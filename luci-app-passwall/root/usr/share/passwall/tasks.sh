#!/bin/sh

## 循环更新脚本

. /usr/share/passwall/utils.sh
LOCK_FILE=${LOCK_PATH}/${CONFIG}_tasks.lock

CFG_UPDATE_INT=0

exec 99>"$LOCK_FILE"
flock -n 99
if [ "$?" != 0 ]; then
	exit 0
fi

while true
do

	if [ "$CFG_UPDATE_INT" -ne 0 ]; then

		stop_week_mode=$(config_t_get global_delay stop_week_mode)
		stop_interval_mode=$(config_t_get global_delay stop_interval_mode)
		stop_interval_mode=$(expr "$stop_interval_mode" \* 60)
		if [ -n "$stop_week_mode" ]; then
			[ "$stop_week_mode" = "8" ] && {
				[ "$(expr "$CFG_UPDATE_INT" % "$stop_interval_mode")" -eq 0 ] && { /etc/init.d/$CONFIG stop > /dev/null 2>&1 & }
			}
		fi

		start_week_mode=$(config_t_get global_delay start_week_mode)
		start_interval_mode=$(config_t_get global_delay start_interval_mode)
		start_interval_mode=$(expr "$start_interval_mode" \* 60)
		if [ -n "$start_week_mode" ]; then
			[ "$start_week_mode" = "8" ] && {
				[ "$(expr "$CFG_UPDATE_INT" % "$start_interval_mode")" -eq 0 ] && { /etc/init.d/$CONFIG start > /dev/null 2>&1 & }
			}
		fi

		restart_week_mode=$(config_t_get global_delay restart_week_mode)
		restart_interval_mode=$(config_t_get global_delay restart_interval_mode)
		restart_interval_mode=$(expr "$restart_interval_mode" \* 60)
		if [ -n "$restart_week_mode" ]; then
			[ "$restart_week_mode" = "8" ] && {
				[ "$(expr "$CFG_UPDATE_INT" % "$restart_interval_mode")" -eq 0 ] && { /etc/init.d/$CONFIG restart > /dev/null 2>&1 & }
			}
		fi

		autoupdate=$(config_t_get global_rules auto_update)
		weekupdate=$(config_t_get global_rules week_update)
		hourupdate=$(config_t_get global_rules interval_update)
		hourupdate=$(expr "$hourupdate" \* 60)
		if [ "$autoupdate" = "1" ]; then
			[ "$weekupdate" = "8" ] && {
				[ "$(expr "$CFG_UPDATE_INT" % "$hourupdate")" -eq 0 ] && { lua $APP_PATH/rule_update.lua log all cron > /dev/null 2>&1 & }
			}
		fi


	fi

	CFG_UPDATE_INT=$(expr "$CFG_UPDATE_INT" + 10)

	sleep 600

done 2>/dev/null
