#@author Uma Mahesh Padisetty uma.padisetty@hotmail.com
#This script reads IPs from arguments / Clipboard and does packetmail lookup for intel
#I know this is bad code for parsing json structures, but anyway serve the purpose
#Hail Nathan Flower for Maintaining the intel about all IPs on packetmail.net

package AutoAnalyst;

use FindBin '$Bin';
use File::Basename;
use lib dirname (__FILE__) . "/local/lib/perl5";		#Loading the dependent libraries. Thanks to Carton for loading them for me
use Scalar::Util 'reftype';
use Text::TabularDisplay;
use Clipboard;
use Data::Validate::IP qw(is_ipv4 is_ipv6);
use Text::Autoformat qw(autoformat break_at break_wrap);

$PROXY = '';
$USERNAME = '';
$PASSWORD = '';
$PROXY_TEST = 'fail'; #Set 'pass' if Proxy is configured
$USERAGENT = 'AutoAnalyst v3.1';
$DEBUG = 0;
$VERY_VERBOSE = 0;
$_PACKETMAIL_KEY = '';					# Contact Nathan Flower for Key for packetmail.net
$packetmail_url = "https://www.packetmail.net/iprep.php/_@@?apikey=$_PACKETMAIL_KEY"; 	# _@@ is replaced with parameter



our $_AA_0, $_AA_1, $_AA_2, $_AA3;

($ARGV[0] =~ /help|-h/i)?usage():packetmail(join(',',@ARGV));


# It     Returns  quick info on IP reputation from packetmail.com if found else "NOT FOUND"
# $_AA_0 contains detailed info (if required by callee)
# $_AA_1 contains create date
# $_AA_2 contains Lists that tracked the IP
# $_AA_3 contains context that tracked the IP

1;
sub usage{
	print "
Usage:
This script reads IPs from arguments / Clipboard and does packetmail lookup for intel

>perl $0 		       - Extracts IPs from clipboard and lookup packetmail intel
>perl $0 [ip1] [ip2] ....   - Lookup packetmail intel for given ips.
>perl $0 help          	- display usage
";
}

sub getPacketmailRep{
	my $value = shift;
	our %packetmail_qrep, %packetmail_rep, %packetmail_cdate;
	our %packetmail_lists, %packetmail_context;
	our @_pmdb;
	my %pm_db;

	return error("Invalid IP") if not is_ipv4($value);

# 	debug("DB: @_pmdb");
# 	if ( igrep($value,@_pmdb) ){
# 		debug("Found This IP Already $value");
# 		$_AA_0 = $packetmail_rep{ $value };
# 		$_AA_1 = $packetmail_cdate{ $value };
# 		$_AA_2 = $packetmail_lists{ $value };
# 		$_AA_3 = $packetmail_context{ $value };
# 
# 		return $packetmail_qrep{ $value };
# 	} 
	debug("Checking packetmail reputation for $value");

	my $data = $pm_db{$value};
	if(is_empty($data)){
		my $url=setParam($packetmail_url,$value);
		$data=getWebPage($url,1);
		debug("Fetching $url");
		debug("Retreived $data");
	}
	
	
	#Retreived JSON can't be easily parsed as nodes are variable
	#Hence manually scraping the data
	# "created_on": "2015-08-20 00:34:21",
	# "hybrid-analisys_raw": {
	# 	"source": "https://www.hybrid-analysis.com/feed?raw",
	# 	"context": "2015-08-19 23:46:32;80;70;\"Gen:Variant.Kazy\";efc66b326ec94f7a74eb575dbe5213b430816d918a3cd1f28cd4e8f78ac0704a;1;\"TESTpoweliks2.exe\";81408;\"PE32 executable (GUI) Intel 80386, for MS Windows\";

	# "cleanmx_virus": {
	# 	"source": "http://lists.clean-mx.com/pipermail/viruswatch/20160303.txt",
	# 	"context": "meow://a7.daoclickxml.com/click?sid=9837f59acc23bd245dd08f266be407ab5287ccb1&cid=0",

	# If the values is not in the repo, it returns below Text
	# "query_result": "No results found, this IP has been added to the 'packetmail_iprep_web_interface' feed"
	# or
	# "packetmail_iprep_web_interface": {
	# 	"source": "https://www.packetmail.net/iprep.php/191.80.10.181",
	# 	"context": "https://www.packetmail.net/iprep.php/191.80.10.181 did not have any reputation data for this IP in the collection so it has been added to the collection because someone requested IP Reputation information about it",
	#   "last_seen": "2015-05-11 12:33:37",
	#   "refreshed": "2015-05-11 12:33:37"
	#clearAA();
	$_AA_0 = "-";   #Default value

	if ($data=~/packetmail_iprep_web_interface/i){
		$packetmail_qrep{ $value } = "-";
		$packetmail_cdate{ $value } = "-";
		$packetmail_rep{ $value } = "-";
		push(@_pmdb,$value);

		return "-"; 
	}


	$data =~ /"created_on": "([^\"]+)"/; my $packetmail_createdate = $1;
	my @packetmail_hits = ($data=~/(\"[^"]+\": {\s*\"source\": \".*?\",\s*\"context\": \".*?\",\s*\"last_seen\": \".*?\",)/g);

	my $quick_info  = $packetmail_createdate; 
	my $detail_info = $packetmail_createdate;
	debug("\ncreated_on: $packetmail_createdate");
	foreach my $blob (@packetmail_hits){
		debug("\n\n$blob");

		$blob =~ /^\"([^\"]+)\"/;	# Sources
		$quick_info .= " / ".trim($1);
		$detail_info .= "\n\n$1";
		$packetmail_lists{ $value } = ($packetmail_lists{ $value })?join(', ',$packetmail_lists{ $value },trim($1)) : trim($1);

		$blob =~ /\"last_seen\": \"(.*?)\",/;
		$detail_info .= "\n\t$1";

		$blob =~ /\"source\": \"(.*?)\",/;
		$detail_info .= " / $1";

		$blob =~ /\"context\": \"(.*?)\",/;
		$detail_info .= "\n\t".squeeze($1,80);
		$packetmail_context{ $value } = ($packetmail_context{ $value })?join(', ',$packetmail_context{ $value },trim($1)) : trim($1);
		
	}

	$_AA_0 = trim($detail_info);
	$_AA_1 = $packetmail_createdate;
	$_AA_2 = $packetmail_list{ $value };
	$_AA_3 = $packetmail_context{ $value };

	$packetmail_qrep{ $value } = $quick_info;
	$packetmail_cdate{ $value } = $packetmail_createdate;
	$packetmail_rep{ $value } = $detail_info;
	
	push(@_pmdb,$value); 
	$pm_db{ $value } = $data;

	return $quick_info;

}

#It display Packetmail Reputation for given IOCs in tabular form
#Max Number of results are not limited to $MAX_LIMIT_IOC
sub packetmail{
	#my @values = readIOCValues(@_);
	my @values = extractIPsFromData(@_);
	my @ips = ();

	foreach my $val (@values){ push(@ips, $val) if is_ipv4($val); }

	my $t;
	my $table = Text::TabularDisplay->new(qw/Query(packetmail) created_on Reputation/);
	my $i=0; my $total_ips = $#ips + 1;
	foreach $t (@ips){
		$i++;
		print "\rChecking Reputation for $i/$total_ips IP";

		my $quick_info = getPacketmailRep($t);		#$_AA_0 holds detailed info, $_AA_1 holds first create date of the indicator
		my @row = ($t, $_AA_1, $_AA_0);
		$table->add(@row);
		$table->add(("","",""));
	}
	($i)?print "\n",$table->render,"\n":print "(*) No IPs found in Clipboard\n";
 	usage() if not $i;
	#flushIO();
}


## Returns WebPage of given URI using CURL with NTLM Authentication
## An Optional UA Parameter can also be sent getWebPage($url,$ua)
sub getWebPage{
	my ($url,$ua) = @_;
	#print "\nProxyTest: $PROXY_TEST";
	if(!$ua){ $ua = $USERAGENT; }
	
	my $tPASS =  $PASSWORD;
	$tPASS = uri_escape($tPASS) if $PASSWORD =~ /\@\%\|/;
	my $cmd ="curl -k --silent";
	$cmd .= " --proxy $PROXY" if defined $PROXY and $PROXY_TEST=~/pass/;
	$cmd .= " --proxy-ntlm --proxy-user \"$USERNAME:$tPASS\"" if defined $USERNAME and $PROXY_TEST=~/pass/i;
	$cmd .= " --user-agent \"$ua\"" if defined $ua;
	$cmd .= " \"$url\"";

	
	my $data = `$cmd`;
	print "\nExecuting cmd:\n$cmd" if $VERY_VERBOSE;
	return "$data";
}


# It consumes raw unprocessed data and returns IPs in it
sub extractIPsFromData{
	my $story_content = shift;
	$story_content = readClipboard() if $story_content =~ /^c(lip)?$/i or is_empty($story_content);
	$story_content =~ s/\[\.\]/\./g;
	my @ips = ($story_content =~ /:\/\/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g);			#Match IPs in URL
	@ips = (@ips,($story_content =~ /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\/|\d)/g));		#Match IPs Ignoring Network Range which starts with tag <b> or <br>
	return uniq(@ips);
}

sub readClipboard{
	my $data = ($^O =~ /darwin/i) ? `pbpaste` : $_CLIP->paste;
	debug($data);
	return $data;
}

sub debug{
	print "\n(( debug )): ".shift if $DEBUG;
}

sub uniq {
    my @tdata =  keys %{{ map { $_ => 1 } @_ }};
	my @xdata;
	foreach $t (@tdata){
		push(@xdata, $t) if not is_empty($t);
	}
	return @xdata;
}

sub is_empty{
	return $_[0] =~ /^\s*$/;
}

# It set the paramter values in given url template
# Placeholder for parameter = _@@
sub setParam{
	my ($url,@values) = @_;
	foreach $val ( @values ){
		$url =~ s/_@@/$val/;
	}
	return $url;
}

sub trim($)
{
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	#$string =~ s/ //;
	return $string;
}

# It takes an array reference / string and squeezes to fixed length
# When displaying data in tabular form, if data is long, table is crippled by going to next line
# Usage: @row = squeeze(\@row, 50);
#		 $val = squeeze($val);
sub squeeze{
	my ($data,$len) = @_;
	return squeezeStr($data,$len) if(is_empty(reftype($data)));
	#If Array
	my $MAX_LENGTH = (defined $len)?$len:65;
	my @newdata; my $t, $newstr;
	foreach $t (@$data){
		$newstr = (length($t)>$MAX_LENGTH)?squeezeStr($t,$MAX_LENGTH):$t;
		push(@newdata,$newstr);
	}
	return @newdata;
}
# It takes a string, max length to which the string is squeezed
# When displaying data in tabular form, if data is long, table is crippled by going to next line
# Hence i would like to sqeeze the data into fixed length.
# 	$str = squeezeStr($str, 15);
sub squeezeStr{
	my ($data, $len) = @_;
	debug ($data);
	return "" if is_empty($data);
	$data =~ s/\s*\n\s*/\n\n\n/g;
	my $out = autoformat ($data, {left=>0, right =>$len, justify=>left, all=>1});
	$out =~ s/\n\s*/\n/g;
	$out .= "\n";
	return trim($out);
}
