use strict;
use DBI;
use XML::LibXML;
use XML::LibXML::XPathContext;
use DateTime::Format::Duration::XSD;
use DateTime::Duration;

my $debug = 0;

my $dbhost = "test1";
my $dbname = "test";
my $dbuser = "root";
my $dbpass = "";

my $configxml = "conf.xml";
my $configrng = "conf.rng";
my $kaspxml = "kasp.xml";
my $kasprng = "kasp.rng";
my $zonelistxml = "zonelist.xml";
my $zonelistrng = "zonelist.rng";

my $dbh =
  DBI->connect( "DBI:mysql:$dbname:$dbhost", $dbuser, $dbpass,
	{ RaiseError => 1, PrintError => 0, PrintWarn => 1, AutoCommit => 0 } );

print "Using version " . XML::LibXML::LIBXML_DOTTED_VERSION . " of libxml.\n"
  if ($debug);

#Clear out the Database. Drop all tables and re-create. FOR TESTING!
initDB();

# Read doc
my $parser = XML::LibXML->new();
my $doc    = $parser->parse_file($kaspxml);

# Validate
my $rngschema = XML::LibXML::RelaxNG->new( location => $kasprng );

# This will exit if validation fails and print errors
eval { $rngschema->validate($doc); };

# Read the XML using XPATH
my $xpc = XML::LibXML::XPathContext->new($doc);

my $kasp = $xpc->find('kasp')->get_node(1);

my $policies = $kasp->findnodes('policy');

foreach my $policy ( $policies->get_nodelist() ) {

	# Create policy
	my $pname = $policy->find("\@name")->string_value();
	my $pdis  = $policy->find("description")->string_value();
	print "Importing policy $pname.\n" if ($debug);
	my $rows =
	  $dbh->do( "INSERT INTO policies (name, description) VALUES (?,?)",
		undef, $pname, $pdis )
	  or die $dbh->errstr;
	if ( $rows == 1 ) {

		# Commit will occur at end if no errors.
		print "Inserted 1 row in to policies (policy = $pname).\n" if ($debug);
	}
	elsif ( $rows == 0 ) {
		$dbh->rollback;
		$dbh->disconnect;
		die
"Error: Attempted to insert 0 rows in to policies (policy = $pname).\n";
	}
	else {
		$dbh->rollback;
		$dbh->disconnect;
		die
"Error: Attempted to insert $rows rows in to policies (policy = $pname).\n";
	}

	$xpc->setContextNode($policy);

	# Read signature section
	my $sig       = $xpc->find('=Signatures')->get_node(1);
	my $resign    = duration2sec( $sig->find('Resign')->string_value() );
	my $refresh   = duration2sec( $sig->find('Refresh')->string_value() );
	my $jitter    = duration2sec( $sig->find('Jitter')->string_value() );
	my $clockskew = duration2sec( $sig->find('InceptionOffset')->string_value() );
	my $valdefault =
	  duration2sec( $sig->find('Validity/Default')->string_value() );
	my $valdenial =
	  duration2sec( $sig->find('Validity/Denial')->string_value() );
	insertpp( "resign",     $resign,     "signature", $pname );
	insertpp( "refresh",    $refresh,    "signature", $pname );
	insertpp( "jitter",     $jitter,     "signature", $pname );
	insertpp( "clockskew",  $clockskew,  "signature", $pname );
	insertpp( "valdefault", $valdefault, "signature", $pname );
	insertpp( "valdenial",  $valdenial,  "signature", $pname );

	# Read denial section
	my $denial = $xpc->find('Denial')->get_node(1);
#	$ttl = duration2sec( $denial->find('ttl')->string_value() );
#	insertpp( "ttl", $ttl, "denial", $pname );

	my $nsec3 = $denial->find('NSEC3')->get_node(1);
	if ($nsec3) {
		insertpp( "version", 3, "denial", $pname );
		my $optout = 0;
		$optout = 1 if ( $nsec3->find('OptOut')->get_node(1) );
		my $resalt     = duration2sec( $nsec3->find('Resalt')->string_value() );
		my $hash       = $nsec3->find('Hash')->get_node(1);
		my $algorithm  = $hash->find('Algorithm')->string_value();
		my $iterations = $hash->find('Iterations')->string_value();
		my $salt       = $hash->find('salt')->get_node(1);
		my $saltlen    = $salt->find("\@length")->string_value();
		insertpp( "optout",     $optout,     "denial", $pname );
		insertpp( "resalt",     $resalt,     "denial", $pname );
		insertpp( "algorithm",  $algorithm,  "denial", $pname );
		insertpp( "iterations", $iterations, "denial", $pname );
		insertpp( "saltlength", $saltlen,    "denial", $pname );
	}

	# Read keys section
	my $keys = $xpc->find('Keys')->get_node(1);
	$ttl = duration2sec( $keys->find('TTL')->string_value() );
	my $retiresafety =
	  duration2sec( $keys->find('RetireSafety')->string_value() );
	my $publishsafety =
	  duration2sec( $keys->find('PublishSafety')->string_value() );
	insertpp( "ttl",           $ttl,           "keys", $pname );
	insertpp( "retiresafety",  $retiresafety,  "keys", $pname );
	insertpp( "publishsafety", $publishsafety, "keys", $pname );

	my $ksk            = $keys->find('KSK')->get_node(1);
	my $algorithm      = $ksk->find('Algorithm')->string_value();
	my $algorithm_len  = $ksk->find("Algorithm/\@length")->string_value();
	my $lifetime       = duration2sec( $ksk->find('Lifetime')->string_value() );
	my $emergency      = $ksk->find('Emergency')->string_value();
	my $repository     = $ksk->find('Repository')->string_value();
	my $respository_id = getresid($repository);
	my $rfc5011        = 0;
	$rfc5011 = 1 if ( $ksk->find('RFC5011')->get_node(1) );
	insertpp( "algorithm",  $algorithm,     "ksk", $pname );
	insertpp( "bits",       $algorithm_len, "ksk", $pname );
	insertpp( "lifetime",   $lifetime,      "ksk", $pname );
	insertpp( "emergency",  $emergency,     "ksk", $pname );
	insertpp( "repository", $repository,    "ksk", $pname );
	insertpp( "rfc5011",    $rfc5011,       "ksk", $pname );

	my $zsk = $keys->find('ZSK')->get_node(1);
	$algorithm      = $zsk->find('Algorithm')->string_value();
	$algorithm_len  = $zsk->find("Algorithm/\@length")->string_value();
	$lifetime       = duration2sec( $ksk->find('Lifetime')->string_value() );
	$emergency      = $zsk->find('Emergency')->string_value();
	$repository     = $zsk->find('Repository')->string_value();
	$respository_id = getresid($repository);
	insertpp( "algorithm",  $algorithm,     "zsk", $pname );
	insertpp( "bits",       $algorithm_len, "zsk", $pname );
	insertpp( "lifetime",   $lifetime,      "zsk", $pname );
	insertpp( "emergency",  $emergency,     "zsk", $pname );
	insertpp( "repository", $repository,    "zsk", $pname );

	# Read zone section
	my $zone = $xpc->find('Zone')->get_node(1);
	my $pd   = duration2sec( $zone->find('PropagationDelay')->string_value() );
	my $soa  = $zone->find('SOA')->get_node(1);
	$ttl = duration2sec( $soa->find('TTL')->string_value() );
	my $min = duration2sec( $soa->find('Minimum')->string_value() );
	insertpp( "propagationdelay", $pd,  "zone", $pname );
	insertpp( "ttl",              $ttl, "zone", $pname );
	insertpp( "min",              $min, "zone", $pname );
	my $serial    = $soa->find('Serial')->string_value();
	my $serial_id = getserialid($serial);
	insertpp( "serial", $serial_id, "zone", $pname );

	# Read parent section
	my $parent = $xpc->find('Parent')->get_node(1);
	my $ttlDS  = duration2sec( $parent->find('DS/TTL')->string_value() );
	$pd  = duration2sec( $parent->find('PropagationDelay')->string_value() );
	$soa = $parent->find('SOA')->get_node(1);
	$ttl = duration2sec( $soa->find('TTL')->string_value() );
	$min = duration2sec( $soa->find('Minimum')->string_value() );
	insertpp( "propagationdelay", $pd,    "parent", $pname );
	insertpp( "ttl",              $ttl,   "parent", $pname );
	insertpp( "ttlds",            $ttlDS, "parent", $pname );
	insertpp( "min",              $min,   "parent", $pname );

}

#Now read from zone list
# Read doc
my $parser1 = XML::LibXML->new();
my $doc1    = $parser1->parse_file($zonelistxml);

# Validate
my $rngschema1 = XML::LibXML::RelaxNG->new( location => $zonelistrng );

# This will exit if validation fails and print errors
eval { $rngschema1->validate($doc1); };

# Read the XML using XPATH
my $xpc1 = XML::LibXML::XPathContext->new($doc1);

my $zonelist = $xpc1->find('ZoneList')->get_node(1);

#Now import zone data
my $zones = $zonelist->findnodes('Zone');
foreach my $zone ( $zones->get_nodelist() ) {
	my $zname   = $zone->find("\@name")->string_value();
	my $zpolicy = $zone->find("Policy")->string_value();
	insertz( $zname, $zpolicy);
}

#Stuff in config.xml now read directly by applications
#but we need the names of the security modules in the DB

# Read doc
my $parser2 = XML::LibXML->new();
my $doc2    = $parser2->parse_file($confxml);

# Validate
my $rngschema2 = XML::LibXML::RelaxNG->new( location => $confrng );

# This will exit if validation fails and print errors
eval { $rngschema2->validate($doc2); };

# Read the XML using XPATH
my $xpc2 = XML::LibXML::XPathContext->new($doc2);

my $configuration = $xpc2->find('Configuration')->get_node(1);

#Now import HSM data


<RepositoryList>
	<Repository>
		<Name>sca6000</Name>
		<Module>/usr/lib/libpkcs11.so</Module>
		<PIN>test:1234</PIN>
		<Capacity>1000</Capacity>
	</Repository>


# If we get here then the policies and zones imported OK
$dbh->commit;

$dbh->disconnect;
exit 0;

# SUBS
sub insertz {
	my $zname   = $_[0];
	my $zpolicy = $_[1];
	my $rows    = $dbh->do(
		"insert into zones (name, policy_id)
	             select ?, p.id from policies p
	             where p.name=?",
		undef, $zname, $zpolicy
	) or die $dbh->errstr;
	if ( $rows == 1 ) {

		# Commit will occur at end if no errors.
		print
"Inserted 1 row in to zones (zone = $zname, policy = $zpolicy, in = $zin, out = $zout).\n"
		  if ($debug);
	}
	elsif ( $rows == 0 ) {
		$dbh->rollback;
		$dbh->disconnect;
		die
"Error: Failed to insert rows in to zones (zone = $zname, policy = $zpolicy, in = $zin, out = $zout).\n";
	}
	else {
		$dbh->rollback;
		$dbh->disconnect;
		die
"Error: Attempted to insert $rows rows in to zones (zone = $zname, policy = $zpolicy, in = $zin, out = $zout).\n";
	}

}

sub duration2sec {
	my $dfdx = DateTime::Format::Duration::XSD->new();
	print "Converting $_[0] to seconds...\n" if $debug;
	my $d = $dfdx->parse_duration( $_[0] );

	print(
"Warning: Converting months and/or years to seconds - you might get something you didn't intend.\n"
	) if ( $d->years != 0 || $d->months != 0 );

	my $sec =
	  ( $d->years * 365 * 86400 ) +
	  ( $d->months * 28 * 24 * 60 * 60 ) +
	  ( $d->weeks * 7 * 24 * 60 * 60 ) +
	  ( $d->days * 24 * 60 * 60 ) +
	  ( $d->hours * 60 * 60 ) +
	  ( $d->minutes * 60 ) +
	  ( $d->seconds );

	return $sec;
}

sub insertpp {
	my $parameter = $_[0];
	my $value     = $_[1];
	my $category  = $_[2];
	my $policy    = $_[3];
	my $rows      = $dbh->do(
		"insert into parameters_policies (parameter_id, policy_id, value)
             select p.id, x.id, ? from parameters p, policies x, categories c
             where p.name=? and c.name=? and c.id=p.category_id and x.name=?",
		undef, $value, $parameter, $category, $policy
	) or die $dbh->errstr;
	if ( $rows == 1 ) {

		# Commit will occur at end if no errors.
		print
"Inserted 1 row in to paramters_policies ($parameter = $value, category = $category, policy = $policy).\n"
		  if ($debug);
	}
	elsif ( $rows == 0 ) {
		$dbh->rollback;
		$dbh->disconnect;
		die
"Error: Failed to insert rows in to paramters_policies ($parameter = $value, category = $category, policy = $policy).\n";
	}
	else {
		$dbh->rollback;
		$dbh->disconnect;
		die
"Error: Attempted to insert $rows rows in to paramters_policies ($parameter = $value, category = $category, policy = $policy).\n";
	}

}

sub getresid {
	my $resname = $_[0];
	print "Looking up security module called $resname.\n" if $debug;
	my $resid =
	  $dbh->selectrow_array( "SELECT id FROM securitymodules WHERE name = ?",
		undef, $resname );
	if ( !defined $resid ) {
		$dbh->rollback;
		$dbh->disconnect;
		die "Error finding security module $resname.\n";
	}
	print "resid: $resid\n" if $debug;
	return $resid;
}

sub getserialid {
	my $serialname = $_[0];
	print "Looking up serial mode called $serialname.\n" if $debug;
	my $serialid =
	  $dbh->selectrow_array( "SELECT id FROM serialmodes WHERE name = ?",
		undef, $serialname );
	if ( !defined $serialid ) {
		$dbh->rollback;
		$dbh->disconnect;
		die "Error finding serial mode $serialname.\n";
	}
	print "serialid: $serialid\n" if $debug;
	return $serialid;
}

sub initDB {

	# Init DB
	print "Clearing out the Database.\n" if $debug;
	my $mysql_cmd =
	  "/usr/local/mysql-5.0.67-osx10.5-x86_64/bin/mysql -u root -h test1";
	open( MYSQL, "|$mysql_cmd" );
	print MYSQL <<EOF;
drop database if exists test;
create database test;
use test;
drop table if exists parameters_policies;
drop table if exists policies;
drop table if exists keypairs;
drop table if exists dnsseckeys;
drop table if exists zones;
drop table if exists adapters;
drop table if exists parameters;
drop table if exists categories;
drop table if exists securitymodules;
drop table if exists serialmodes;

# now create the tables

# security modules - store information about all the sms used
create table securitymodules (
  id            tinyint not null auto_increment,    # id for sm
  name          varchar(30) not null,  # name of the sm
  description   varchar(255),
  location      varchar(280) not null,
  capacity      mediumint not null,
  pin           varchar(255) null default null,

  constraint primary key (id)
)ENGINE=InnoDB;

# categories - stores the possible categories (or uses) of parameters
create table categories (
  id            tinyint not null auto_increment,    # id for category_id
  name          varchar(30) not null,  # name of the category_id

  constraint primary key (id)
)ENGINE=InnoDB;

# parameters - stores the types of parameters available
create table parameters (
  id            mediumint not null auto_increment,    # id for parameters
  name          varchar(30) not null,  # name of the parameter
  description   varchar(255), # description of the paramter
  category_id         tinyint not null,      # category_id of the parameter

  constraint primary key (id),
  constraint unique (name, category_id),
  constraint foreign key (category_id) references categories (id)
)ENGINE=InnoDB;

# adapters - stores the types of signer adapters available
create table adapters (
  id            tinyint not null auto_increment,    # id for adapter
  name          varchar(30) not null,  # name of the adapter
  description   varchar(255), # description of the adapter

  constraint primary key (id)
)ENGINE=InnoDB;

create table serialmodes (
  id            tinyint auto_increment,    # id for serial mode
  name          varchar(30),  # name of the serial mode
  description   varchar(255), # description of the serial mode

  constraint primary key (id)
)ENGINE=InnoDB;

# policies - 
create table policies (
  id            mediumint not null auto_increment,    # id
  name          varchar(30) not null,  # name of the policy
  description   varchar(255), # description of the

  constraint primary key (id),
  constraint unique (name)
)ENGINE=InnoDB;

# zones - stores the zones
create table zones(
  id            mediumint not null auto_increment,    # id
  name          varchar(30) not null ,  # name of the parameter
  in_adapter_id      tinyint not null,      # type of inbound adaptor for this zone
  out_adapter_id     tinyint not null,      # type of outbound adapter for this zone
  policy_id     mediumint not null,

  constraint primary key (id),
  constraint foreign key (in_adapter_id) references adapters (id),
  constraint foreign key (out_adapter_id) references adapters (id),
  constraint foreign key (policy_id) references policies (id)
)ENGINE=InnoDB;

# stores the private key info
create table keypairs(
  id     smallint not null auto_increment,
  HSMkey_id  varchar(255) not null,
  algorithm     tinyint not null,             # algorithm code
  size          smallint,
  securitymodule_id          tinyint,                      # where the key is stored
  state         tinyint,                      # state of the key (defines valid fields)
  generate      timestamp null default null,  # time key inserted into database
  publish       timestamp null default null,  # time when key published into the zone
  ready         timestamp null default null,  # time when the key is ready for use
  active        timestamp null default null,  # time when the key was made active
  retire        timestamp null default null,  # time when the key retires
  dead          timestamp null default null,  # time when key is slated for removal
  policy_id        mediumint,
  compromisedflag tinyint,
  publickey     varchar(1024),                # public key data
  
  constraint primary key (id),
  constraint foreign key (securitymodule_id) references securitymodules (id),
  constraint foreign key (policy_id) references policies (id)
)ENGINE=InnoDB;

# stores meta data about keys (actual keys are in a (soft)hsm)
create table dnsseckeys (
  id            int  not null auto_increment,  # unique id of the key
  keypair_id    smallint,
  zone_id        mediumint,
  keytype       smallint not null,             # zsk or ksk (use code in dnskey record)
  origkeytag    smallint not null,            # original key tag
  revokedkeytag smallint not null,            # revoked key tag
  digest1       varchar(20),                  # sha1 digest
  digest256     varchar(32),                  # sha256 digest


  constraint primary key (id),
  constraint foreign key (zone_id) references zones (id),
  constraint foreign key (keypair_id) references keypairs (id)
)ENGINE=InnoDB;

# parameters_policies - join table to hold the values of parameters
create table parameters_policies (
  id            mediumint auto_increment,    # id
        parameter_id mediumint not null,
        policy_id mediumint not null,
        value int,                                # integer value of this key
        constraint primary key (id),
        constraint foreign key (parameter_id) references parameters (id),
        constraint foreign key (policy_id) references policies (id)
)ENGINE=InnoDB;

# insert default data
# default security modules
insert into securitymodules (name, description, location, capacity, pin) values ("sca6000-1", "sca6000", "pkcs11.so", 1000, "1234");
insert into securitymodules (name, description, location, capacity, pin) values ("softHSM-01", "the best soft hsm in the world", "pkcs11.so", 1000, "1234");

# default categories
insert into categories (name) values ("signature");
insert into categories (name) values ("denial");
insert into categories (name) values ("ksk");
insert into categories (name) values ("zsk");
insert into categories (name) values ("keys");
insert into categories (name) values ("enforcer");
insert into categories (name) values ("zone");
insert into categories (name) values ("parent");

# default serial number modes
insert into serialmodes (name, description) values ("unixtime", "seconds since 1 Jan 1970");
insert into serialmodes (name, description) values ("counter", "add one everytime updated");
insert into serialmodes (name, description) values ("datecounter", "YYYYMMDDXX");

# default parameters
insert into parameters (name, description, category_id) select "resign", "re-signing interval", id from categories where name="signature";
insert into parameters (name, description, category_id) select "refresh", "how old a signature may become before it needs to be re-signed",id from categories where name="signature";
insert into parameters (name, description, category_id) select "jitter", "jitter to use in signature inception and expiration times", id from categories where name="signature";
insert into parameters (name, description, category_id) select "clockskew", "estimated max clockskew expected in clients", id from categories where name="signature";
insert into parameters (name, description, category_id) select "ttl", "ttl for RRSIGS", id from categories where name="signature";
insert into parameters (name, description, category_id) select "valdefault", "signature validity period", id from categories where name="signature";
insert into parameters (name, description, category_id) select "valdenial", "nsec(3) validity period", id from categories where name="signature";

insert into parameters (name, description, category_id) select "ttl", "ttl for nsec(3) rrs", id from categories where name="denial";
insert into parameters (name, description, category_id) select "version", "nsec version (0 or 3)", id from categories where name="denial";
insert into parameters (name, description, category_id) select "optout", "opt out flag for nsec3", id from categories where name="denial";
insert into parameters (name, description, category_id) select "resalt", "re-salting interval", id from categories where name="denial";
insert into parameters (name, description, category_id) select "algorithm", "nsec3 algorithm", id from categories where name="denial";
insert into parameters (name, description, category_id) select "iterations", "nsec3 iterations", id from categories where name="denial";
insert into parameters (name, description, category_id) select "saltlength", "nsec3 salt length", id from categories where name="denial";

insert into parameters (name, description, category_id) select "ttl", "ttl for ksk rrs", id from categories where name="keys";
insert into parameters (name, description, category_id) select "retiresafety", "ksk retirement safety factor", id from categories where name="keys";
insert into parameters (name, description, category_id) select "publishsafety", "ksk publish safety factor", id from categories where name="keys";

insert into parameters (name, description, category_id) select "algorithm", "ksk algorithm", id from categories where name="ksk";
insert into parameters (name, description, category_id) select "bits", "ksk key size", id from categories where name="ksk";
insert into parameters (name, description, category_id) select "lifetime", "ksk lifetime", id from categories where name="ksk";
insert into parameters (name, description, category_id) select "emergency", "number of ksks is use at any one time", id from categories where name="ksk";
insert into parameters (name, description, category_id) select "repository", "default ksk sm (for newly generated keys)", id from categories where name="ksk";
insert into parameters (name, description, category_id) select "rfc5011", "are we doing rfc5011?", id from categories where name="ksk";

insert into parameters (name, description, category_id) select "algorithm", "zsk algorithm", id from categories where name="zsk";
insert into parameters (name, description, category_id) select "bits", "zsk key size", id from categories where name="zsk";
insert into parameters (name, description, category_id) select "lifetime", "zsk lifetime", id from categories where name="zsk";
insert into parameters (name, description, category_id) select "emergency", "number of zsks is use at any one time", id from categories where name="zsk";
insert into parameters (name, description, category_id) select "repository", "default zsk sm (for newly generated keys)", id from categories where name="zsk";

insert into parameters (name, description, category_id) select "propagationdelay", "Dp", id from categories where name="zone";
insert into parameters (name, description, category_id) select "ttl", "ttl of the soa", id from categories where name="zone";
insert into parameters (name, description, category_id) select "min", "min of the soa", id from categories where name="zone";
insert into parameters (name, description, category_id) select "serial", "how serial no are changed", id from categories where name="zone";

insert into parameters (name, description, category_id) select "propagationdelay", "Dp", id from categories where name="parent";
insert into parameters (name, description, category_id) select "ttl", "ttl of the soa", id from categories where name="parent";
insert into parameters (name, description, category_id) select "min", "min of the soa", id from categories where name="parent";
insert into parameters (name, description, category_id) select "ttlds", "ttl of the ds", id from categories where name="parent";

#insert into parameters (name, description, category_id) select "keycreate", "policy for key creation 0=fill the hsm, 1=only generate minimum needed", id from categories where name="enforcer";
insert into parameters (name, description, category_id) select "interval", "run interval", id from categories where name="enforcer";
insert into parameters (name, description, category_id) select "keygeninterval", "interval between key generation runs", id from categories where name="enforcer";
insert into parameters (name, description, category_id) select "backupdelay", "how old must a new key be before it can be assumed to have been backed up", id from categories where name="enforcer";

# default adapters
insert into adapters (name, description) values ("file", "all signers should be able to read files.");
insert into adapters (name, description) values ("axfr", "axfr adapter to the signer.");

insert into policies (name, description) values ("opendnssec", "special policy for enforcer config");
commit;
EOF
	close MYSQL;
	print "Done clearing out the Database.\n" if $debug;
}
