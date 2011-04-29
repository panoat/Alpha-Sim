
## Panoat Chuchaisri
## FW Simulator
##

set priVer	01		;# Primary version #
set secVer	11		;# Secondary version #

set logDir	"/home/gato/ns-log"
set namtr	"$logDir/Sim$priVer-$secVer.nam"	;# nam trace file
set fwtr	"$logDir/Sim$priVer-$secVer-fw.out"	;# firewall trace file
set fwgrph	"$logDir/Sim$priVer-$secVer-fwgrph.out"	;# firewall graph file
set pmgrph	"$logDir/Sim$priVer-$secVer-pmgrph.out"	;# packmime graph file
set tr		"$logDir/Sim$priVer-$secVer.out"	;# ns trace file
set httptr 	"$logDir/Sim$priVer-$secVer-http.out"	;# packmime http trace file

#---- Parameters ------------------------------------------------------------
set nmtrOn	"off"			;# turn nam trace on/off
set fwtrOn	"on"			;# turn fw trace on/off
set fwgrphOn	"on"			;# turn fw graph on/off
set pmgrphOn	"on"			;# turn pm graph on/off
set trOn	"off"			;# turn ns trace on/off
set httptrOn	"off"			;# turn packmime trace on/off

set atkNum	100			;# number of attacker nodes
set arate	0.5			;# attack rate (packet/sec)
set ackDly	9.5			;# 3rd ACK delay (sec) -1 for "disable"
set pmrate	1			;# new connection rate (connect/sec)
set fwspfOn	"off"			;# turn firewall spoof packet on/off

set pmstr	0.1			;# start packmime traffic
set pmstp	1500.1			;# stop packmime traffic
set stop	3000.0			;# total simulation runtime (sec)
#----------------------------------------------------------------------------

set CLIENT  0
set SERVER  1

set CLN		0
set FW		1
set SRV		2
set ATK		3

proc finish {} {
	global ns trfd trOn

	$ns flush-trace
	if {$trOn eq "on"} {close $trfd}
##	exec nam $namtr &
	exit 0
}

proc create-topology {} {
	global ns fw fwtr fwgrph
	global node atkNum CLN FW SRV ATK
	global fwtrOn fwgrphOn

	#Create & label nodes
	set node($CLN) [$ns node]
	set node($FW) [$ns node]
	set node($SRV) [$ns node]
	$node($CLN) label "CLN"		;#Client node
	$node($FW) label "FW"		;#Firewall
	$node($SRV) label "SRV"		;#Server


#Create FW & Reconnect node's entry point to FW agent (Sniffing)
set fw [new Agent/Firewall]
if {$fwtrOn eq "on" && $fwtr ne ""} {$fw set-logfile $fwtr}
if {$fwgrphOn eq "on" && $fwgrph ne ""} {$fw set-grphfile $fwgrph}
$fw set-server $SRV
#puts "Node entry: [$node($FW) entry] fw entry: [$fw target]"
$ns attach-agent $node($FW) $fw
$node($FW) insert-entry [new RtModule] $fw "target"
#puts "Node entry: [$node($FW) entry] fw entry: [$fw target]"


	#Create links
	$ns duplex-link $node($CLN) $node($FW) 10Mb 5ms DropTail	;# CLN - FW
	$ns duplex-link $node($FW) $node($SRV) 10Mb 5ms DropTail	;# FW - SRV


	#Attacker node creation loop
	for { set i $ATK } { $i < $ATK + $atkNum } { incr i } {
		set node($i) [$ns node]
		$node($i) label "ATK$i"
		$ns duplex-link $node($i) $node($FW) 10Mb 5ms DropTail
	}
}

proc create-trace {} {
	global ns tr namtr
	global nmtrOn

	if {$nmtrOn eq "on" && $namtr ne ""} {
		$ns namtrace-all [open $namtr w]
	}

	set trfd [open $tr w]
	$ns trace-all $trfd 
	return $trfd
}

## MAIN ##

set ns [new Simulator]
if { $trOn eq "on" } {set trfd [create-trace]}

create-topology

# Setup Packmime (Web Traffic generator)
set rate $pmrate
set pm [new PackMimeDDOS]
$pm set-client $node($CLN)
$pm set-server $node($SRV)
$pm set-victim $node($SRV)
$pm set-rate $rate
$pm set-atk-rate $arate
$pm set-ack-delay $ackDly
$pm set-http-1.1
$pm set-debug 0

for { set i 0 } { $i < $atkNum } { incr i } {
	$pm set-attacker $node([expr $ATK + $i])
}

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

if { $httptrOn eq "on" && $httptr ne "" } {
	$pm set-outfile $httptr		;# Http trace
}

if { $pmgrphOn eq "on" } { $pm set-graphfile $pmgrph }

# Enable Firewall
if {$fwspfOn eq "on"} {$fw enable-spoof} else {$fw enable}

#Start packmime traffic
$ns at $pmstr "$pm start"
$ns at $pmstp "$pm stop"

$ns at $stop "finish"
$ns run
