# ==================================
# Simulation parameters
# ==================================
set version	01
set logDir	"/home/gato/ns-log"
set namtr	"$logDir/beta$version.nam"	;# nam trace file
set nstr	"$logDir/beta$version.out"	;# ns trace file

#set val(pt_common) 8.564879510890936E-4

set val(chan)	Channel/WirelessChannel		; # channel
set val(prop)	Propagation/TwoRayGround	; # propagation 
set val(range)	7				; # transmission range
set val(netif)	Phy/WirelessPhy			; # phy
set val(mac)	Mac/802_11			; # mac
set val(ifq) 	Queue/DropTail			; # queue
set val(ll) 	LL				; # link layer
set val(ant) 	Antenna/OmniAntenna		; # antenna 
set val(ifqlen)	200				; # queue length
set val(rp)	AODV				; # routing protocol
set val(en)	EnergyModel/Battery		; # energy model
set val(n_pas)		1			; # number os access points
set val(n_common) 	4000			; # number of common nodes
set val(nn)	[expr $val(n_pas) \
		+ $val(n_common)]		; # number of nodes
set val(x)		200.0			; # x lenght of simulation area
set val(y)		200.0			; # y lenght of simulation area

set val(disseminating_type)	2		; # common node disseminating type (ON DEMAND)
set val(disseminating_interval)	5.0		; # common node disseminating interval

set val(start)			3.0		; # simulation start time
set val(stop)			30.0		; # simulation stop time

set val(port)			2020		; # default port

set val(common_engy)		10.0		; # common node initial energy
set val(access_engy)		100.0		; # access point initial energy

set trace(nam)		OFF

set trace(mac)		OFF
set trace(router)	OFF
set trace(agent)	OFF
set trace(movement)	OFF

# =======================================
# Global variables
# =======================================
set ns_	[new Simulator]

set traceFile	[open $nstr w]
$ns_ trace-all $traceFile
$ns_ use-newtrace

if {$trace(nam) eq ON } {
	set namtraceFile [open $namtr w]  
	$ns_ namtrace-all-wireless $namtraceFile $val(x) $val(y)
}

set topo [new Topography]
$topo load_flatgrid $val(x) $val(y)

create-god $val(nn)
set rng [new RNG]
$rng seed 0

# =============================================
# Procedure to create a common node application
# =============================================
proc create_common_app {destination_id disseminating_type disseminating_interval} {
	set app_ [new Application/SensorBaseApp/CommonNodeApp]
	$app_ set destination_id_ $destination_id
	$app_ set disseminating_type_ $disseminating_type
	$app_ set disseminating_interval_ $disseminating_interval
	return $app_
}

# ====================================================
# Procedure to create a access point node application. 
# ====================================================
proc create_access_point_app {destination_id} {
	set app_ [new Application/AccessPointApp]
	$app_ set destination_id_ $destination_id
	return $app_
}

#=========================================
# Calculating the receiving threshold (RXThresh_ for Phy/Wireless)
# Wei Ye, weiye@isi.edu, 2000
#=========================================
proc Friis { Pt Gt Gr lambda L d} {
	set M [expr $lambda / (4 * 3.14159265359 * $d)]
	return [expr ($Pt * $Gt * $Gr * ($M * $M)) / $L]
}

proc TwoRay { Pt Gt Gr ht hr L d lambda } {
        set crossover_dist [expr (4 * 3.14159265359 * $ht * $hr) / $lambda]

        if { $d < $crossover_dist } {
                return [Friis $Pt $Gt $Gr $lambda $L $d]
        } else {
                return [expr $Pt * $Gt * $Gr * ($hr * $hr * $ht * $ht) / ($d * $d * $d * $d * $L)]
	}
}

# =================================
# Antenna Settings
# =================================
Antenna/OmniAntenna set X_ 0
Antenna/OmniAntenna set Y_ 0
Antenna/OmniAntenna set Z_ 1.5
Antenna/OmniAntenna set Gt_ 1.0
Antenna/OmniAntenna set Gr_ 1.0

# =================================
# Wireless Phy Settings --- (MICA2 mote)
# =================================
#Phy/WirelessPhy set CPThresh_ 10.0		;# no info
#Phy/WirelessPhy set CSThresh_ 1.559e-11	;# no info
Phy/WirelessPhy set RXThresh_ [TwoRay 0.281838 [$val(ant) set Gt_] [$val(ant) set Gr_] 0.8 0.8 1.0 $val(range) 0.125]
#Phy/WirelessPhy set Rb_ 2*1e6			;# no info
Phy/WirelessPhy set Pt_ 0.281838
Phy/WirelessPhy set freq_ 2.4e09
Phy/WirelessPhy set L_ 1.0
Phy/WirelessPhy set bandwidth_ 28.8*10e3 	;#28.8 kbps
			
Node/MobileNode/SensorNode set sensingPower_ 0.015
Node/MobileNode/SensorNode set processingPower 0.024
Node/MobileNode/SensorNode set instructionsPerSecond_ 8000000

set counter 0

# =================================
# Procedure to create a common node 
# =================================
proc create_common_node {} {
	global val ns_ node_ topo udp_ app_ gen_ counter rng trace

#Phy/WirelessPhy set Pt_ $val(pt_common)
	$ns_ node-config -sensorNode ON \
	-adhocRouting $val(rp) \
	-llType $val(ll) \
	-macType $val(mac) \
	-ifqType $val(ifq) \
	-ifqLen $val(ifqlen) \
	-antType $val(ant) \
	-propType $val(prop) \
	-energyModel $val(en) \
	-phyType $val(netif) \
	-channelType $val(chan) \
	-topoInstance $topo \
	-agentTrace  $trace(agent)\
	-routerTrace $trace(router) \
	-macTrace $trace(mac) \
	-rxPower 0.024 \
	-txPower 0.036 \
	-initialEnergy $val(common_engy) \
	-movementTrace $trace(movement)
	set node_($counter) [$ns_ node]
	$node_($counter) random-motion 0
	set x [$rng uniform 0.0 $val(x)]
	set y [$rng uniform 0.0 $val(y)]
	$node_($counter) set X_ $x
	$node_($counter) set Y_ $y
	$node_($counter) set Z_ 0.0
	set interval [$rng uniform 0.0 1.0]
	set udp_($counter) [new Agent/UDP]

#puts "* Common node [$node_($counter) node-addr] = $counter created at ($x, $y)"

#	set distance 10000000
#	set initial [expr $val(n_pas)]

#	for {set j $initial} {$j < $initial} {incr j} {
#		set x_father [$node_($j) set X_]
#		set y_father [$node_($j) set Y_]
#		set x_son [$node_($counter) set X_]
#		set y_son [$node_($counter) set Y_]
#		set x_temp [expr pow([expr $x_father-$x_son],2)]
#		set y_temp [expr pow([expr $y_father-$y_son],2)]
#		set temp_distance [expr sqrt([expr $x_temp + $y_temp])]
#		if {$temp_distance < $distance} {
#			set distance $temp_distance
			set val(father_addr) [$node_(0) node-addr]
#		}
#	}

	set app_($counter) [create_common_app $val(father_addr) $val(disseminating_type) $val(disseminating_interval)]
	$node_($counter) attach $udp_($counter) $val(port)
	$node_($counter) add-app $app_($counter)

#	set processing_($counter) [new Processing/AggregateProcessing]

	$app_($counter) node $node_($counter)
	$app_($counter) attach-agent $udp_($counter)

#	$app_($counter) attach-processing $processing_($counter)
#	$processing_($counter) node $node_($counter)

	$ns_ at [expr $val(start) + 1 + $interval] "$app_($counter) start"
	$ns_ at $val(stop) "$app_($counter) stop"

#	set gen_($counter) [create_temp_data_generator 3.0 0 25.0 1.0]
#	$app_($counter) attach_data_generator $gen_($counter)

	incr counter

}

# ========================================
# Procedure to create a access point node 
# ========================================
proc create_access_point {} {
	global ns_ val node_ app_ udp_ counter topo trace
#	Phy/WirelessPhy set Pt_ 0.2818
	$ns_ node-config -sensorNode ON \
	-adhocRouting $val(rp) \
	-llType $val(ll) \
	-macType $val(mac) \
	-ifqType $val(ifq) \
	-ifqLen $val(ifqlen) \
	-antType $val(ant) \
	-propType $val(prop) \
	-energyModel $val(en) \
	-phyType $val(netif) \
	-channelType $val(chan) \
	-topoInstance $topo \
	-agentTrace $trace(agent) \
	-routerTrace $trace(router) \
	-macTrace $trace(mac) \
	-rxPower 0.5 \
	-txPower 0.5 \
	-initialEnergy $val(access_engy) \
	-movementTrace $trace(movement)
	set node_($counter) [$ns_ node]
	$node_($counter) random-motion 0
	set  udp_($counter) [new Agent/UDP]
	set app_($counter) [create_access_point_app [$node_(0) node-addr]]
	$node_($counter) attach $udp_($counter) $val(port)
	$app_($counter) attach-agent $udp_($counter)
	$node_($counter) set X_ [expr $val(x) / 2]
	$node_($counter) set Y_ [expr $val(y) / 2]
	$node_($counter) set Z_ 0.0

	$app_($counter) set request_type_ 0	;# BUFFER = 1, REAL = 0
	$ns_ at [expr $val(start)+0.5] "$app_($counter) add_temp_data_param 5 0"
	$ns_ at [expr $val(start)+1] "$app_($counter) send_request"
	$ns_ at [expr $val(stop)+1] "$app_($counter) stop"
	incr counter

}

# =================================================================
# Procedures to control common node and cluster head node creation
# =================================================================
create_access_point

for {set i 0} {$i < $val(n_common)} {incr i} {
	create_common_node
}

# Define node initial position in nam
for {set i 0} {$i < $val(nn)} { incr i } {
# defines the node size for nam
$ns_ initial_node_pos $node_($i) [expr $val(x) / 40]
}

# =========================
# Simulation
# =========================

$ns_ at [expr $val(stop)+2.0] "puts \"NS EXITING...\" ; $ns_ halt"

$ns_ at [expr $val(stop)+2.0] "$ns_ nam-end-wireless $val(stop)"

$ns_ at [expr $val(stop)+2.1] "finish"

proc finish {} {
	global ns_ traceFile namtraceFile trace
	$ns_ flush-trace
	close $traceFile
	if{$trace(nam) eq ON}{close $namtraceFile}
	flush stdout
}

puts "Starting Simulation..."
$ns_ run
