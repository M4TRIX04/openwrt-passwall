#!/bin/sh
# B1 contract only: definitions, deliberately NOT sourced by app.sh or LuCI.
# No UCI/cache/process I/O. Inputs are canonical selectors, not legacy `node`.
# Outputs describe requested routing, never verified listener readiness.
passwall_resolve_node_pair() {
	PW_NODE_TCP= PW_NODE_UDP= PW_NODE_UDP_SELECTOR= PW_NODE_LAYOUT=closed PW_NODE_INHERIT=0
	[ "$#" = 2 ] || return 1
	PW_NODE_TCP="$1"
	PW_NODE_UDP_SELECTOR="$2"
	case "$2" in
		tcp) PW_NODE_UDP="$1" ;;
		*) PW_NODE_UDP="$2" ;;
	esac
	if [ -n "$PW_NODE_TCP" ] && [ -n "$PW_NODE_UDP" ]; then
		if [ "$PW_NODE_TCP" = "$PW_NODE_UDP" ]; then
			PW_NODE_LAYOUT=combined
		else
			PW_NODE_LAYOUT=split
		fi
	elif [ -n "$PW_NODE_TCP" ]; then
		PW_NODE_LAYOUT=tcp
	elif [ -n "$PW_NODE_UDP" ]; then
		PW_NODE_LAYOUT=udp
	fi
	return 0
}

# mode, use_global_config, ACL TCP/UDP selectors, successful global TCP/UDP IDs.
# Global inputs must come from complete current-start endpoint records, not UCI.
# mode=0 ignores all inactive selectors. Missing mode/use_global retain 0/0.
passwall_resolve_acl_node_pair() {
	passwall_resolve_node_pair '' ''
	[ "$#" = 6 ] || return 1
	case "${1:-0}" in
		0) return 0 ;;
		1) ;;
		*) return 1 ;;
	esac
	case "${2:-0}" in
		0) passwall_resolve_node_pair "$3" "$4" ;;
		1)
			passwall_resolve_node_pair "$5" "$6"
			PW_NODE_INHERIT=1
			;;
		*) return 1 ;;
	esac
}
