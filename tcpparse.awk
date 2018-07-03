#!/usr/bin/awk -f

############################################################
## 
##     PARSE TCPDUMP TCP PACKETS AND MEASURE REQ->RESP TIME
## 
##   A tiny utility capable to parse output of full
## tcpdump output targeted to TCP protocol. Works
## best with numeric values (ip/port) rather than 
## rsolved DNS/service.
##   Example tcpdump command:
##   # tcpdump -i any -ttnnSs0 tcp
## 
##   Feel free to pipe it to this script
## 
## @author: Darius Juodokas
## @date  : 2018-07-03
## 
############################################################


## FUNCTIONS ## {{{

function contains(arr, val) {
    for (item in arr) {
        if (arr[item] == val) {
            return true;
        }
    }
    return false;
}


function printRecord(pending_since, t, duration, client_ip, client_port, server_ip, server_port, len, others) {
    format = "%s - %s %f %s:%s <-> %s:%s, %d, %s\n";
    
    printf(format, pending_since, t, duration, client_ip, client_port, server_ip, server_port, len, others);
}

## }}}

BEGIN {
    
    true=1;
    false=0;
    
    _server_ports="80 443";
    split(_server_ports, SERVER_PORTS, " ");
}

{

    ## INIT ## {{{
    syn=false;
    ack=false;
    fin=false;
    rst=false;
    payl=false;

    t=$1;
    src=$3;
    dst=$5;
    flags=$7;

    others_idx=8;
    others="";

    options=nil;
    ack_id=nil;
    seq_id=nil;
    win_id=nil;
    len=nil;
    

    src_ip=src;
    src_port=src;

    sub(/:.*$/, "", src);
    sub(/:.*$/, "", dst);

    dst_ip=dst;
    dst_port=dst;

    server_ip = nil;
    server_port = nil;
    client_ip=nil;
    client_port=nil;


    request=false;
    response=false;

    ## }}}

    ## PARSE {{{
#    flags = substr(flags, 2, length(flags)-3);
    sub(/^.*\[/, "", flags);
    sub(/\].*$/, "", flags);

    sub(/\.[0-9a-zA-Z\-]+.$/, "", src_ip);
    #sub(/^([0-9]+\.){4}/, "", src_port);
    sub(/^.*\./, "", src_port);

    sub(/\.[0-9a-zA-Z\-]+.$/, "", dst_ip);
    #sub(/^([0-9]+\.){4}/, "", dst_port);
    sub(/^.*\./, "", dst_port);

#    print "src_ip="src_ip", dst_ip="dst_ip
#    print "src_port="src_port", dst_port="dst_port
#    print "src="src", dst="dst

    if ($others_idx == "seq") {
        others_idx++;
        seq_id = $others_idx;
        others_idx++;
    }
    if ($others_idx == "ack") {
        others_idx++;
        ack_id = $others_idx;
        others_idx++;
    }
    if ($others_idx == "win") {
        others_idx++;
        win_id = $others_idx;
        others_idx++;
    }

    if ($others_idx == "options") {
        options=$0;
        sub(/^.*options \[/, "", options);
        sub(/\].*/, "", options);

        while ($others_idx !~ /^.*\].*$/) {
            others_idx++;
        }
        others_idx++;
    }

    if ($others_idx == "length") {
        others_idx++;
        len=$others_idx;
        sub(/[,:.*$]/, "", len);
        others_idx++;
    }

    while (others_idx < NF) {
        others += " ";
        others += $others_idx;
        others_idx++;
    }
    
    
    
    split(flags, flags_arr, "");

    if (contains(flags_arr, "S")) {
        syn=true;
    }
    if (contains(flags_arr, "P")) {
        payl=true;
    }
    if (contains(flags_arr, "R")) {
        rst=true;
    }
    if (contains(flags_arr, "F")) {
        fin=true;
    }
    if (contains(flags_arr, ".")) {
        ack=true;
    }
    
    ## }}}
    
    ## ASSIGN ## {{{

    if (contains(SERVER_PORTS, src_port) == true) {
        response = true;
        server_ip = src_ip;
        server_port = src_port;
        client_ip = dst_ip;
        client_port = dst_port;
    } else if (contains(SERVER_PORTS, dst_port) == true) {
        request = true;
        server_ip = dst_ip;
        server_port = dst_port;
        client_ip = src_ip;
        client_port = src_port;
    } else if (src_port < dst_port) { ## Making a wild assumption that server ports are lower numbers
        guess=true;
        response = true;
        server_ip = src_ip;
        server_port = src_port;
        client_ip = dst_ip;
        client_port = dst_port;
    } else {
    #    print "port " + src_port + " is in ports ";
        guess = true;
        request = true;
        server_ip = dst_ip;
        client_ip = src_ip;
        server_port = dst_port;
        client_port = src_port;
    }

    ## }}}



    ## FORMAT, DECIDE AND PRINT {{{
    
    #print client_ip ":" client_port " " server_ip ":" server_port;

    KEY = sprintf("%s:%s_%s:%s", client_ip, client_port, server_ip, server_port);

    pending_since = PENDING[KEY];
    if (request == true) {
       # print "REQUEST: "$0
        if (payl == true) {
            if (!pending_since) {
                PENDING[KEY] = t;
            }
        }
    } else if (response == true) {

        #print "RESPONSE: " $0
        if (payl == true) {
            if (pending_since) {
                duration = t - pending_since;
                delete PENDING[KEY];
        
                printRecord(pending_since, t, duration, client_ip, client_port, server_ip, server_port, len, others);
            } else {
         #       print "unseen";
            }
        }

    } else {
        print "ERROR";
    }
    
    
    ## }}}
    
}

END {
    
}
