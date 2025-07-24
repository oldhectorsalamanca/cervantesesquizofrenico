#!/usr/bin/perl

use strict;
use warnings;
use Net::DNS;
use Getopt::Long;
use Term::ANSIColor;

my ($dnsserver, $nocolor, $timeout, $verbose);
my $domain;
my @results;
$timeout = 10;

GetOptions(
    'dnsserver=s' => \$dnsserver,
    'nocolor'     => \$nocolor,
    'timeout=i'   => \$timeout,
    'verbose'     => \$verbose,
    'h|help'      => \&usage,
);

$domain = lc shift @ARGV or usage();

unless ($nocolor) { print color 'bold green'; }

print <<'ASCII_ART';
                            .........',,;::;:ccc;,'.                                      
                        .';:;;::ccldxxxxxxxxkdlc;...                                    
                        ':lloddddddxxkkkkOOOOOkxd:....                                   
                        .,cloddxxxxxxxxxkOOOOOOOOkd:'...                                   
                    .,lodddxxxkkkkkkkkOOOOOOOkxdc,..                                    
                    'codxxxxxkkOkOOOOOOOOOOkkxdoc,..                                    
                    .,coodxxkkkkkkkOkOOOOOOkkxxdoc,...                                   
                    .;coodxxkkxkkkOOOOOOOOOkkxdolc,'..                                   
                    'clodxxxkxxkkkOOOOOOOOkkxxdolc;,'.                                   
                    .;ldxxkkkkkkOOOOOO00OOkxxxxdoc:;''.                                   
                    ..',;ldkkOOkkkxdddxkOOOxxxdxdoc:;,'..                                  
                ..':coc;:oxkxdllloooooooddxxdxdl:;;;,..                                  
                .,:,':cc:;;cdxxdolodlcoxkkxoodxxo::cclllc;.                                
            'odl:,';;;'':oxxdoolod:.'loodxddxdc:llclodoxo.                               
            'okkxoc;',,:ccodddxxxxollloolldxxxdllddl:lxxxkOd.                              
        .;dkkkko:;:ccclxxdoodxxxdddodddxkkkxoldddc;:ddkOOko..                             
        .lxkkxdxo:',clldxdooodxxxkkxxxkkxxkxdooxxoloddxO0OOko:                             
        'lxkxkxxxdc,.;:cddocccldxxxxxdddxxxxxoodxxdddxO0OOOkkdl.                            
    .,lxkkkkxkxc,',,',;,'':ooodxddooododdoooodxxdxOOOkxxxxdo;                            
    .',lxxkkkkkxc,.'',,;:::coooodddddooooooolloxxOKK00OOO0dodl.                           
    ..,:dxxkkxxoc'..,clcclllllclooddoooooooolldKKKK00OOOkkdoxdl.                          
    .....ldxkOkko'.,;:;,,;:cloolccllooooolollcoO00000000Oxddloddc.                       
....'.'lddxkkx:...';;,;;::loooolccloollc::cdkkOOOOO00Oxoddooddc.                       
.''..':llodxdl,'..':c:;:clodollllllllcc:ldkOOOO0OOOkxxdodddddd'                         
    .''..'oxkxdl,'...';c:;clloddolcclllc:cdkkkOOO000KOddoooloxxxx:                         
.;:;'..lxxdolc:,'..,::;clodddddoc;:llokOkkkkkO00K0ddxddooddxxd.                         
.ccc;,';lodxxxxxdc'..,;:llloddxdolloxkkkOkkO000O00xodxkxoddxo'                           
.:c:'.'::;coxkkkOd:,..;cllloddoodxO00OkkOkkOO0Ododdlldxddxxko.                           
.',..,:::;:xkxxxdol:';clllooddxO0K00OOOkxOOOxoccloloodddxxd;                            
    '..';;;;:dxxkkOOOxc;clodxO00kO00000Okdddxdodddol:loddc;'                              
    ....',::odoodxkOOOkdoxO000000kO00kolcccoooxxddo;:lodo.                                
        .cc:cdllc;:lxkOxdkkkkkxdxxxkdlllooddloxxdoc;cool,                                 
        ;c:;;ldolc:::lxdloolllooooodxxdoodxodxxxddl,;,.                                   
        .::;:cooccccclollodxdodxxdlloxkOolxxkkkxdd;                                                                            
ASCII_ART
print "~~~~~~~~~~~~~~ Domain $domain ~~~~~~~~~~~~~~\n";
unless ($nocolor) { print color 'reset'; }

my $res = Net::DNS::Resolver->new(
    tcp_timeout => $timeout,
    udp_timeout => $timeout,
    defnames    => 0,
);

$res->nameservers($dnsserver) if $dnsserver;

# Host's Addresses (A records)
printheader("Host's addresses:\n");
my $packet = $res->query($domain);
if ($packet) {
    foreach my $rr (grep { $_->type eq 'A' } $packet->answer) {
        push @results, $rr->address;
        printrr($rr->string);
    }
} elsif ($verbose) {
    warn "$domain A query failed: ", $res->errorstring, "\n";
}

# Name Servers (NS records)
printheader("Name Servers:\n");
$packet = $res->query($domain, 'NS');
if ($packet) {
    foreach my $rr (grep { $_->type eq 'NS' } $packet->answer) {
        printrr($rr->string);
    }
} else {
    warn "$domain NS query failed: ", $res->errorstring, "\n";
}

# Mail Servers (MX records)
printheader("Mail (MX) Servers:\n");
$packet = $res->query($domain, 'MX');
if ($packet) {
    foreach my $rr (grep { $_->type eq 'MX' } $packet->answer) {
        my $mxhost = $rr->exchange;
        my $priority = $rr->preference;
        my $mx_packet = $res->query($mxhost, 'A');
        if ($mx_packet) {
            foreach my $a_rr (grep { $_->type eq 'A' } $mx_packet->answer) {
                printf("%-40s %-8s %-5s %-8s %10s\n",
                    $mxhost . ".", $priority, "IN", "A", $a_rr->address);
            }
        } else {
            # Still show MX even if A lookup fails
            printf("%-40s %-8s %-5s %-8s %10s\n",
                $mxhost . ".", $priority, "IN", "MX", "(no A record)");
        }
    }
} elsif ($verbose) {
    warn "$domain MX query failed: ", $res->errorstring, "\n";
}

# Run Nmap on each found host A record (discreet and fast scan)
unless ($nocolor) { print color 'bold green'; }
print("\n~ Silent Scan on Host's IP(s) ~\n\n");

foreach my $ip (@results) {
    unless ($nocolor) { print color 'bold white'; }
    printf("PORT     STATE    SERVICE <IP:%s>\n", $ip);
    unless ($nocolor) { print color 'reset'; }

    # Build and run the nmap command
    my $nmap_cmd = "nmap -T2 -sS --top-ports 10 -Pn $ip";
    my @output = `$nmap_cmd`;

    foreach my $line (@output) {
        if ($line =~ /^(\d+\/tcp)\s+(\w+)\s+(\S+)/) {
            printf("%-10s %-6s %-10s\n", $1, $2, $3);
        }
    }
}

# Run WafW00f in non-intrusive detection mode (-t 3) for http and https
unless ($nocolor) { print color 'bold green'; }
print("\n~ 'Silent' WAF Detection ~ SKIPPED TO PREVENT DETECTION (remove '=pod' and '=cut' to uncomment)\n");

=pod
foreach my $proto ('http', 'https') {
    my $target = "$proto://$domain";
    unless ($nocolor) { print color 'bold white'; }
    print "\nProtocol $proto:\n";
    unless ($nocolor) { print color 'reset'; }

    my $cmd = "wafw00f $target 2>/dev/null";
    my @waf_output = `$cmd`;

    my $found = 0;
    foreach my $line (@waf_output) {
        chomp $line;
        if ($line =~ /behind/) {
            print "$line\n";
            $found = 1;
        }
    }
    print "No WAF detected or not enough evidence.\n" unless $found;
}
=cut

# --- Metadata extraction with MetaFinder ---
unless ($nocolor) { print color 'bold green'; }
print "\n~ Metadata Extraction ~\n";
unless ($nocolor) { print color 'reset'; }

my $output_file = "meta_results_$domain.txt";

# MetaFinder command: uses Bing and Google, with 4 threads
my $meta_cmd = "metafinder -d $domain -o $output_file -l 50 -t 4 -go -bi 2>&1";
my @meta_output = `$meta_cmd`;

my $show = 0;
foreach my $line (@meta_output) {
    if ($line =~ /Searching/) {
        $show = 1;
    }
    print $line if $show;
}

print "\nResults saved in '$output_file'.\n";



# ---------- Subroutines ----------

sub printrr {
    my $output  = shift;
    my @outputA = split(/\s+/, $output);
    printf("%-40s %-8s %-5s %-8s %10s\n",
        $outputA[0], $outputA[1], $outputA[2], $outputA[3], $outputA[4]);
}

sub printheader {
    my ($header) = @_;
    unless ($nocolor) { print color 'bold white'; }
    print "\n$header";
    unless ($nocolor) { print color 'reset'; }
}

sub usage {
    print <<"USAGE";
Usage: $0 [options] <domain>
USAGE
    exit(1);
}
