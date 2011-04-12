#include <gtest/gtest.h>

#include "conf.pb.h"
#include "kasp.pb.h"
#include "kaspxml.h"

const char *kasp_test_doc = 
"<KASP>\n"
	"<Policy name=\"default\">\n"
		"<Description>A default policy that will amaze you and your friends</Description>\n"
		"<Signatures>\n"
			"<Resign>PT2H</Resign>\n"
			"<Refresh>P3D</Refresh>\n"
			"<Validity>\n"
				"<Default>P7D</Default>\n"
				"<Denial>P7D</Denial>\n"
			"</Validity>\n"
			"<Jitter>PT12H</Jitter>\n"
			"<InceptionOffset>PT3600S</InceptionOffset>\n"
		"</Signatures>\n"
		"<Denial>\n"
			"<NSEC3>\n"
			"<Resalt>P100D</Resalt>\n"
			"<Hash>\n"
				"<Algorithm>1</Algorithm>\n"
				"<Iterations>5</Iterations>\n"
				"<Salt length=\"8\"/>\n"
			"</Hash>\n"
			"</NSEC3>\n"
		"</Denial>\n"
		"<Keys>\n"
			"<TTL>PT3600S</TTL>\n"
			"<RetireSafety>PT3600S</RetireSafety>\n"
			"<PublishSafety>PT3600S</PublishSafety>\n"
			"<Purge>P14D</Purge>\n"
			"<KSK>\n"
				"<Algorithm length=\"2048\">8</Algorithm>\n"
				"<Lifetime>P1Y</Lifetime>\n"
				"<Repository>SoftHSM</Repository>\n"
			"</KSK>\n"
			"<ZSK>\n"
				"<Algorithm length=\"1024\">8</Algorithm>\n"
				"<Lifetime>P30D</Lifetime>\n"
				"<Repository>SoftHSM</Repository>\n"
			"</ZSK>\n"
		"</Keys>\n"
		"<Zone>\n"
			"<PropagationDelay>PT43200S</PropagationDelay>\n"
			"<SOA>\n"
				"<TTL>PT3600S</TTL>\n"
				"<Minimum>PT3600S</Minimum>\n"
				"<Serial>unixtime</Serial>\n"
			"</SOA>\n"
		"</Zone>\n"
		"<Parent>\n"
			"<PropagationDelay>PT9999S</PropagationDelay>\n"
			"<DS>\n"
				"<TTL>PT3600S</TTL>\n"
			"</DS>\n"
			"<SOA>\n"
				"<TTL>PT172800S</TTL>\n"
				"<Minimum>PT10800S</Minimum>\n"
			"</SOA>\n"
		"</Parent>\n"
		"<Audit>\n"
		"</Audit>\n"
	"</Policy>\n"
"</KASP>\n";


TEST(KaspXML, LoadKaspXmlToProtocolBuffer)
{
	kasp::pb::KaspDocument *doc = new kasp::pb::KaspDocument;

	ASSERT_TRUE(read_kasp_pb_from_xml_memory(doc,kasp_test_doc,strlen(kasp_test_doc))); //read_kasp_pb_from_xml_file(doc,"kasp.xml");

	delete doc;
}

TEST(KaspXML, VerifyKaspXmlToProtocolBuffer)
{
	kasp::pb::KaspDocument *doc = new kasp::pb::KaspDocument;

	ASSERT_TRUE(read_kasp_pb_from_xml_memory(doc,kasp_test_doc,strlen(kasp_test_doc))); //read_kasp_pb_from_xml_file(doc,"kasp.xml");
	
	EXPECT_TRUE( doc->has_kasp() );
	EXPECT_TRUE( doc->kasp().policies_size()==1 );
	EXPECT_TRUE( doc->kasp().policies(0).has_signatures() );
	
	EXPECT_TRUE( doc->kasp().policies(0).has_denial() );
	
	EXPECT_TRUE( doc->kasp().policies(0).has_keys() );
	
	EXPECT_TRUE( doc->kasp().policies(0).has_zone() );
	
	EXPECT_TRUE( doc->kasp().policies(0).has_parent() );
	
	delete doc;
}

int main(int argc, char **argv)
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
