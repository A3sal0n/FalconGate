##! FalconGate port and address scan detection (Zeek 8 compatible).
##!
##! Zeek 8 no longer ships the misc/scan policy, so FalconGate provides its own.
##! The installer copies this file to
##! /opt/zeek/share/zeek/policy/FalconGate/port-scan.zeek and local.zeek loads
##! it with "@load FalconGate/port-scan".
##!
##! It tracks failed TCP connection attempts per scanner with SumStats and
##! raises two notices in notice.log:
##!
##!   Scan::Port_Scan    - one host probed many ports on a single victim.
##!   Scan::Address_Scan - one host probed the same port on many victims.
##!
##! The module is named "Scan" so the notice names match what the FalconGate
##! notice log parser (lib/logparser.py) looks for. Port_Scan notices always
##! carry both $src (scanner) and $dst (victim), which the parser requires.

@load base/frameworks/notice
@load base/frameworks/sumstats

module Scan;

export {
	redef enum Notice::Type += {
		## A host attempted connections to many ports on a single victim.
		Port_Scan,
		## A host attempted connections to the same port on many victims.
		Address_Scan,
	};

	## Time window in which failed attempts are counted for a port scan.
	const port_scan_interval = 5min &redef;

	## Number of unique destination ports on one victim that must fail
	## within port_scan_interval before a Port_Scan notice is raised.
	const port_scan_threshold = 15.0 &redef;

	## Time window in which failed attempts are counted for an address scan.
	const addr_scan_interval = 5min &redef;

	## Number of unique victims that must fail on the same port within
	## addr_scan_interval before an Address_Scan notice is raised.
	const addr_scan_threshold = 25.0 &redef;

	## Scanners to ignore entirely, e.g. the FalconGate appliance itself,
	## which runs its own scheduled nmap scans of the home network.
	## Example in local.zeek: redef Scan::ignore_scanners += { 192.168.1.1 };
	const ignore_scanners: set[addr] = {} &redef;

	## Destination ports that should never count toward a scan.
	const ignore_ports: set[port] = {} &redef;

	## Hooks that can veto an observation. Breaking out of the hook
	## (with "break") stops the attempt from being counted.
	global addr_scan_policy: hook(scanner: addr, victim: addr, scanned_port: port);
	global port_scan_policy: hook(scanner: addr, victim: addr, scanned_port: port);
}

hook addr_scan_policy(scanner: addr, victim: addr, scanned_port: port) &priority=10
	{
	if ( scanner in ignore_scanners || scanned_port in ignore_ports )
		break;
	}

hook port_scan_policy(scanner: addr, victim: addr, scanned_port: port) &priority=10
	{
	if ( scanner in ignore_scanners || scanned_port in ignore_ports )
		break;
	}

event zeek_init() &priority=5
	{
	# Port scan: key = scanner + victim, observe the unique ports probed.
	local rp: SumStats::Reducer = [$stream="scan.port.fail",
	                               $apply=set(SumStats::UNIQUE),
	                               $unique_max=double_to_count(port_scan_threshold + 2)];
	SumStats::create([$name="falcongate-port-scan",
	                  $epoch=port_scan_interval,
	                  $reducers=set(rp),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["scan.port.fail"]$unique + 0.0;
	                  	},
	                  $threshold=port_scan_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["scan.port.fail"];
	                  	local side = Site::is_local_addr(key$host) ? "local" : "remote";
	                  	local victim = to_addr(key$str);
	                  	local msg = fmt("%s scanned at least %d unique ports of host %s in %s",
	                  	                key$host, r$unique, victim, r$end - r$begin);
	                  	NOTICE([$note=Port_Scan,
	                  	        $src=key$host,
	                  	        $dst=victim,
	                  	        $sub=side,
	                  	        $msg=msg,
	                  	        $identifier=cat(key$host, victim)]);
	                  	}]);

	# Address scan: key = scanner + port, observe the unique victims probed.
	local ra: SumStats::Reducer = [$stream="scan.addr.fail",
	                               $apply=set(SumStats::UNIQUE),
	                               $unique_max=double_to_count(addr_scan_threshold + 2)];
	SumStats::create([$name="falcongate-addr-scan",
	                  $epoch=addr_scan_interval,
	                  $reducers=set(ra),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	return result["scan.addr.fail"]$unique + 0.0;
	                  	},
	                  $threshold=addr_scan_threshold,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
	                  	{
	                  	local r = result["scan.addr.fail"];
	                  	local side = Site::is_local_addr(key$host) ? "local" : "remote";
	                  	local msg = fmt("%s scanned at least %d unique hosts on port %s in %s",
	                  	                key$host, r$unique, key$str, r$end - r$begin);
	                  	NOTICE([$note=Address_Scan,
	                  	        $src=key$host,
	                  	        $p=to_port(key$str),
	                  	        $sub=side,
	                  	        $msg=msg,
	                  	        $identifier=cat(key$host, key$str)]);
	                  	}]);
	}

function add_sumstats(id: conn_id, reverse: bool)
	{
	local scanner = id$orig_h;
	local victim = id$resp_h;
	local scanned_port = id$resp_p;

	if ( reverse )
		{
		scanner = id$resp_h;
		victim = id$orig_h;
		scanned_port = id$orig_p;
		}

	if ( hook port_scan_policy(scanner, victim, scanned_port) )
		SumStats::observe("scan.port.fail", [$host=scanner, $str=cat(victim)],
		                  [$str=cat(scanned_port)]);

	if ( hook addr_scan_policy(scanner, victim, scanned_port) )
		SumStats::observe("scan.addr.fail", [$host=scanner, $str=cat(scanned_port)],
		                  [$str=cat(victim)]);
	}

# The originator saw its SYN answered by a RST, or reset the connection
# before any data was exchanged (typical of SYN/half-open scans).
function is_failed_conn(c: connection): bool
	{
	if ( (c$orig$state == TCP_SYN_SENT && c$resp$state == TCP_RESET) ||
	     (((c$orig$state == TCP_RESET && c$resp$state == TCP_SYN_ACK_SENT) ||
	       (c$orig$state == TCP_RESET && c$resp$state == TCP_ESTABLISHED && "S" in c$history)) &&
	      /[Dd]/ !in c$history) )
		return T;
	return F;
	}

# Same as is_failed_conn, but with Zeek having flipped the connection
# direction (e.g. it only saw the responder's side first).
function is_reverse_failed_conn(c: connection): bool
	{
	if ( (c$resp$state == TCP_SYN_SENT && c$orig$state == TCP_RESET) ||
	     (((c$resp$state == TCP_RESET && c$orig$state == TCP_SYN_ACK_SENT) ||
	       (c$resp$state == TCP_RESET && c$orig$state == TCP_ESTABLISHED && "s" in c$history)) &&
	      /[Dd]/ !in c$history) )
		return T;
	return F;
	}

# SYN sent but never answered (filtered/closed port that drops packets).
event connection_attempt(c: connection)
	{
	add_sumstats(c$id, "H" in c$history);
	}

# SYN answered with a RST (closed port).
event connection_rejected(c: connection)
	{
	add_sumstats(c$id, "s" in c$history);
	}

event connection_reset(c: connection)
	{
	if ( is_failed_conn(c) )
		add_sumstats(c$id, F);
	else if ( is_reverse_failed_conn(c) )
		add_sumstats(c$id, T);
	}
