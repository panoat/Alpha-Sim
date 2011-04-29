
## Panoat Chuchaisri
## FW Simulator
##


set priVer	01		;# Primary version #
set secVer	9		;# Secondary version #

set opt(namtr)	"Sim$priVer-$secVer.nam"	;# nam trace file
set opt(fwtr)	"Sim$priVer-$secVer-fw.out"	;# firewall trace file
set opt(tr)	"Sim$priVer-$secVer.out"	;# ns trace file
set opt(httptr) "Sim$priVer-$secVer-http.out"	;# packmime http trace file
set opt(node)	3				;# number of nodes

set opt(pmstr)	0.2				;# start packmime traffic
set opt(pmstp)	1800.0				;# stop packmime traffic
set opt(stop)	1801.0				;# total simulation runtime (sec)

set opt(tcp)	TCP
set opt(sink)	TCPSink

set CLIENT  0
set SERVER  1

set CLN		0
set FW		1
set SRV		2
set ATK		3

proc finish {} {
	global ns opt trfd

	$ns flush-trace
	close $trfd
##	exec nam $opt(namtr) &
	exit 0
}

proc create-topology {} {
	global ns opt
	global node CLN FW SRV ATK

	#Create & label nodes
	set node($CLN) [$ns node]
	set node($FW) [$ns node]
	set node($SRV) [$ns node]
	set node($ATK) [$ns node]
	$node($CLN) label "CLN"		;#Client node
	$node($FW) label "FW"		;#Firewall
	$node($SRV) label "SRV"		;#Server
	$node($ATK) label "ATK"		;#Attacker


#Reconnect node's entry point to FW agent (Sniffing)
set fw [new Agent/Firewall]
$fw set-outfile $opt(fwtr)
#puts "Node entry: [$node($FW) entry] fw entry: [$fw target]"
$ns attach-agent $node($FW) $fw
$node($FW) insert-entry [new RtModule] $fw "target"
#puts "Node entry: [$node($FW) entry] fw entry: [$fw target]"


	#Create links
	$ns duplex-link $node($CLN) $node($FW) 10Mb 5ms DropTail	;# CLN - FW
	$ns duplex-link $node($ATK) $node($FW) 10Mb 5ms DropTail	;# ATK - FW
	$ns duplex-link $node($FW) $node($SRV) 10Mb 5ms DropTail	;# FW - SRV

}

proc create-trace {} {
	global ns opt

	set trfd [open $opt(tr) w]
	$ns trace-all $trfd
	if {$opt(namtr) != ""} {
		$ns namtrace-all [open $opt(namtr) w]
	}
	return $trfd
}

## MAIN ##

set ns [new Simulator]
set trfd [create-trace]

create-topology

# Setup Packmime (Web Traffic generator)
set rate 1
set atkrate 5
set pm [new PackMimeDDOS]
$pm set-attacker $node($ATK)
$pm set-server $node($SRV)
$pm set-rate $rate
$pm set-attack-rate $atkrate
$pm set-http-1.1
$pm set-debug 0

# Setup Packmime random variables
global defaultRNG

# Create RNGs
set flowRNG [new RNG]
set reqsizeRNG [new RNG]
set rspsizeRNG [new RNG]

# Create Random Variables
set flow_arrive [new RandomVariable/PackMimeHTTPFlowArrive $rate]
set req_size [new RandomVariable/PackMimeHTTPFileSize $rate $CLIENT]
set rsp_size [new RandomVariable/PackMimeHTTPFileSize $rate $SERVER]

# Assign RNGs to Random Variables
$flow_arrive use-rng $flowRNG
$req_size use-rng $reqsizeRNG
$rsp_size use-rng $rspsizeRNG

# Set Packmime variables
$pm set-flow_arrive $flow_arrive
$pm set-req_size $req_size
$pm set-rsp_size $rsp_size
$pm set-outfile $opt(httptr)	;# Http trace

#Create firewall agent and attach to FW node
set fw [new Agent/Firewall]
$fw set-outfile $opt(fwtr)
$fw set-server $SRV
$fw enable
$ns attach-agent $node($FW) $fw

#Start packmime traffic
$ns at $opt(pmstr) "$pm start"
$ns at $opt(pmstp) "$pm stop"

$ns at $opt(stop) "finish"
$ns run
