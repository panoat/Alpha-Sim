# ==================================
# Simulation parameters
# ==================================
set version	02
set logDir	"/home/gato/ns-log"
set namtr	"$logDir/beta$version.nam"	;# nam trace file
set nstr	"$logDir/beta$version.out"	;# ns trace file

set AF_MODE	0	;# authentication first mode
set FF_MODE	1	;# forwarding first mode
set KP_MODE	2	;# key pool mode
set KC_MODE	3	;# key chain mode

#set val(pt_common) 8.564879510890936E-4

set val(chan)	Channel/WirelessChannel		; # channel
set val(prop)	Propagation/TwoRayGround	; # propagation 
set val(netif)	Phy/WirelessPhy			; # phy
set val(mac)	Mac/802_11			; # mac
set val(ifq) 	Queue/DropTail			; # queue
set val(ll) 	LL				; # link layer
set val(ant) 	Antenna/OmniAntenna		; # antenna 
set val(ifqlen)	200				; # queue length
set val(rp)	AODV				; # routing protocol
set val(en)	EnergyModel/Battery		; # energy model
set val(n_pas)		1			; # number os access points
set val(n_common) 	3000			; # number of common nodes
set val(nn)	[expr $val(n_pas) \
		+ $val(n_common)]		; # number of nodes
set val(x)		200.0			; # x lenght of simulation area
set val(y)		200.0			; # y lenght of simulation area

; # transmission range - calculate from number of nodes and simulation area
set val(range)	[expr sqrt( 4.5 * $val(x) * $val(y) / $val(n_common) )]

set val(disseminating_type)	2		; # common node disseminating type (ON DEMAND)
set val(disseminating_interval)	5.0		; # common node disseminating interval

set val(start)			100.0		; # simulation start time
set val(rep)			30		; # no. of broadcast message sent
set val(interval)		100.0		; # time between each broadcast (sec)
set val(stop)			[expr $val(start) + $val(rep) * $val(interval) + 1]

set val(port)			2020		; # default port

set val(common_engy)		10.0		; # common node initial energy
set val(access_engy)		100.0		; # access point initial energy

;#----- Key Pool mode parameters -------------------
set val(ks_num)			10		; # number of sets in key pool (n)
set val(fake_ks_num)		1		; # number of fake key set (must be <= n)
set val(ks_size)		4		; # number of keys in a set (m)
set val(lc_ks_size)		2		; # number of keys stored locally (k)
set val(bf_kps)			2		; # number of key/set to be add to BF (h)
;#--------------------------------------------------

;#----- Key Chain mode parameters ------------------
set val(kcs_num)		30		; # number of set in key chain pool (n')
set val(fake_kcs_num)		3		; # number of fake set in kc pool (<= n')
set val(lc_kc_size)		3		; # number of local keys (k)
;#--------------------------------------------------

set val(bf_hnum)		1		; # number of hashes for BF (q)
set val(bfv_size)		64		; # BFV size (bit) (r)
set val(bf_delta)		0		; # BFV bit reducer (<= r)

;#======================================================#
;#		PACKET FORWARDING MODE			#
;# $AF_MODE, $FF_MODE, $KP_MODE, $KC_MODE		#
;#======================================================#
set val(fwd_mode)		$KC_MODE
;#======================================================#

set val(ecc_delay)		1.6		; # ECC sig verification delay (sec)
set hop_delay			0.0006		; # delay per byte of hash operation(sec)
set ds_size			20		; # digital signature size (byte)
; # BF verification delay (sec)
if {$val(fwd_mode) eq $KP_MODE} {
	set val(bf_delay) [expr $hop_delay * $val(bf_hnum) * $val(lc_ks_size) * $ds_size]
} elseif {$val(fwd_mode) eq $KC_MODE} {
	set val(bf_delay) [expr $hop_delay * ($val(bf_hnum) + 1) * $val(lc_kc_size) * $ds_size]
} else { set val(bf_delay) 0.05 }

;#--- Tracing --------------
set trace(ns)		OFF
set trace(nam)		OFF
set trace(mac)		OFF
set trace(router)	OFF
set trace(agent)	OFF
set trace(movement)	OFF

# =======================================
# Global variables
# =======================================
set ns_	[new Simulator]

if {$trace(ns) eq ON} {
set traceFile	[open $nstr w]
} else { set traceFile [open /dev/null w] }

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

# ===================================
# BFV parameter settings
#====================================
Agent/AODV set key_set_num_ 		$val(ks_num)
Agent/AODV set fake_key_set_num_ 	$val(fake_ks_num)
Agent/AODV set key_set_size_ 		$val(ks_size)
Agent/AODV set local_key_set_size_ 	$val(lc_ks_size)
Agent/AODV set kchain_set_num_		$val(kcs_num)
Agent/AODV set fake_kcs_num_		$val(fake_kcs_num)
Agent/AODV set local_kchain_size_	$val(lc_kc_size)		
Agent/AODV set bf_key_per_set_ 		$val(bf_kps)
Agent/AODV set bf_hash_num_ 		$val(bf_hnum)
Agent/AODV set bf_vector_size_ 		$val(bfv_size)
Agent/AODV set bf_delta_		$val(bf_delta)
Agent/AODV set bf_delay_		$val(bf_delay)
Agent/AODV set ecc_delay_		$val(ecc_delay)
Agent/AODV set fwd_mode_		$val(fwd_mode)

set counter 0

# =================================
# Procedure to create a common node 
# =================================
proc create_common_node { id } {
	global val ns_ node_ topo udp_ app_ gen_ rng trace

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
	set node_($id) [$ns_ node]
	$node_($id) random-motion 0

	set interval [$rng uniform 0.0 1.0]
	set udp_($id) [new Agent/UDP]

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

	set app_($id) [create_common_app $val(father_addr) $val(disseminating_type) $val(disseminating_interval)]
	$node_($id) attach $udp_($id) $val(port)
	$node_($id) add-app $app_($id)

#	set processing_($counter) [new Processing/AggregateProcessing]

	$app_($id) node $node_($id)
	$app_($id) attach-agent $udp_($id)

#	$app_($counter) attach-processing $processing_($counter)
#	$processing_($counter) node $node_($counter)

	$ns_ at [expr $val(start) + $interval] "$app_($id) start"
	$ns_ at $val(stop) "$app_($id) stop"

#	set gen_($counter) [create_temp_data_generator 3.0 0 25.0 1.0]
#	$app_($counter) attach_data_generator $gen_($counter)

}

proc position_common_node { id } {
	global rng val node_

	set x [$rng uniform 0.0 $val(x)]
	set y [$rng uniform 0.0 $val(y)]
	$node_($id) set X_ $x
	$node_($id) set Y_ $y
	$node_($id) set Z_ 0.0
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
#	$ns_ at [expr $val(start)+0.5] "$app_($counter) add_temp_data_param 5 0"

#$ns_ at [expr $val(start)+9.5] "$app_($counter) add_temp_data_param 5 0"
#$ns_ at [expr $val(start) + 10] "$app_($counter) send_request"

#	$ns_ at [expr $val(stop)+1] "$app_($counter) stop"
	incr counter

}

# =================================================================
# Procedures to control common node and cluster head node creation
# =================================================================
create_access_point
set dummy_rt [new Agent/AODV [$node_(0) node-addr]]	;# dummy agent for stat-summary command

# send WSN connectivity probe
#Agent/AODV set fwd_mode_		1		;# fwd-first mode
#$ns_ at [expr $val(start) * 0.1] "$app_(0) add_temp_data_param 5 0"
#$ns_ at [expr $val(start) * 0.1] "$app_(0) send_request"
#$ns_ at [expr $val(start) * 0.8] "$dummy_rt stat-summary"
#Agent/AODV set fwd_mode_		$val(fwd_mode)

# send_request + stat-summary loop for batch analysis
for {set j 0} {$j < $val(rep)} { incr j } {
	set strtm [expr $val(start) + ($j * $val(interval)) ]
	set endtm [expr $val(start) + (($j + 0.8) * $val(interval)) ]
	$ns_ at $strtm "$app_(0) add_temp_data_param 5 0"
	$ns_ at $strtm "$app_(0) send_request"
#	$ns_ at $strtm "puts \"Start=$strtm, End=$endtm \""
	$ns_ at $endtm "$dummy_rt stat-summary"
	$ns_ at $endtm "puts stderr \"finish round $j\""
}
$ns_ at [expr $val(stop)+1] "$app_(0) stop"

for {} {$counter < $val(nn)} {incr counter} {
	create_common_node $counter
	position_common_node $counter
}

# Define node initial position in nam
for {set i 0} {$i < $val(nn)} { incr i } {
# defines the node size for nam
$ns_ initial_node_pos $node_($i) [expr $val(x) / 40]
}



# =========================
# Simulation
# =========================
#$ns_ at [expr $val(stop)-1.0] "$dummy_rt stat-summary"

$ns_ at [expr $val(stop)+2.0] "$ns_ halt"

$ns_ at [expr $val(stop)+2.0] "$ns_ nam-end-wireless $val(stop)"

$ns_ at [expr $val(stop)+2.2] "finish"

proc finish {} {
	global ns_ traceFile namtraceFile trace
	$ns_ flush-trace
	if{$trace(ns) eq ON}{close $traceFile}
	if{$trace(nam) eq ON}{close $namtraceFile}
	flush stdout
}

puts "Starting Simulation... with range $val(range)"
$ns_ run
