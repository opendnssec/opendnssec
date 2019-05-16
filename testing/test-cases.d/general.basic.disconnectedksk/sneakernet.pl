#!/bin/env perl
use strict;
use warnings;
use MIME::Base64;
use XML::LibXML qw( );

my $parser = XML::LibXML->new();
my $document = XML::LibXML->load_xml(location => $ARGV[0]);

foreach my $keyNode ($document->findnodes('//SignerConfiguration/Zone/Keys/Key')) {
    my $flagsValue = $keyNode->findvalue('Flags/text()');
    if($flagsValue eq "257") {
      my $locatorNode = $keyNode->find('Locator')->get_node(1);
      my $locatorValue = $keyNode->findvalue('Locator/text()');
      my $resourcerecord = "";
      my $keytag = "skip";
      open(FILE, $ARGV[1]);
      while(<FILE>) {
        if(m/;;Key: locator $locatorValue algorithm \d+ flags 257 publish \d+ ksk \d+ zsk \d+ keytag (\d+)/) {
          $keytag=$1;
        }
        if(m/^(.*	.*	IN	DNSKEY	257 \d+ \d+ .*) ;{id = $keytag \(ksk\), size .*}$/) {
           print "found" . $1 . "\n";
           $resourcerecord = encode_base64($1);
        }
      }
      close(FILE);
      foreach my $locatorNode ($keyNode->findnodes('Locator')) {
        $keyNode->removeChild($locatorNode);
      }
      my $resourceNode = XML::LibXML::Element->new('ResourceRecord');
      $resourceNode->appendText($resourcerecord);
      $keyNode->appendChild($resourceNode);
    }
}

my $resourcerecord = "";
open(FILE, $ARGV[1]);
while(<FILE>) {
        if(m/^(.*	.*	IN	RRSIG	DNSKEY \d+ \d+ \d+ \d+ \d+ \d+ .* .*); \{locator .* flags 257}$/) {
           my $resourceNode = XML::LibXML::Element->new('SignatureResourceRecord');
           $resourceNode->appendText(encode_base64($1));
           $document->find('//SignerConfiguration/Zone/Keys')->get_node(1)->appendChild($resourceNode);;
        }
}
close(FILE);

open(FILE, "| xmllint --format - > " . $ARGV[0] . ".new");
print FILE $document->toString();
close(FILE);
