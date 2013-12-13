/* $Id$ */

/*
 * Copyright (c) 2011 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 pb-orm-tree-tests.cc

 Contains test cases to test with messages defined in the tree.proto file
 *****************************************************************************/

#include <string>
#include <ostream>

#include "pb-orm-tree-tests.h"
#include "timecollector.h"
#include "pbormtest.h"

#include "tree.pb.h"

CPPUNIT_TEST_SUITE_REGISTRATION(TreeTests);

static bool treeInsert(OrmConn conn, int NUM_BRANCHES)
{
	OrmTransaction trans(conn);
	::pb_orm_test::Tree tree;
	tree.set_version(3);
	::pb_orm_test::Trunk *trunk = tree.mutable_trunk();
	for (int b=0; b<NUM_BRANCHES; ++b) {
		::pb_orm_test::Branch *branch = trunk->add_branches();
		for (int l=0; l<10; ++l) {
			std::ostringstream leaf;
			leaf << "Leaf " << b << l;
			branch->add_leaves(leaf.str());
		}
	}
	pb::uint64 treeid;
	if (!OrmMessageInsert(conn,tree,treeid))
		return false;
	trans.commit();
	return true;
}

void TreeTests::setUp()
{
	Stopwatch swatch("TreeTests::setUp");

	conn = NULL;

	OrmInitialize();

	__setup_conn(conn);

	OrmDropTable(conn,::pb_orm_test::Tree::descriptor());

	CPPUNIT_ASSERT(OrmCreateTable(conn,::pb_orm_test::Tree::descriptor()));
}

void TreeTests::tearDown()
{
	Stopwatch swatch("TreeTests::tearDown");

    if (conn) {
    	CPPUNIT_ASSERT(OrmDropTable(conn,::pb_orm_test::Tree::descriptor()));
		OrmConnClose(conn);
    }
    OrmShutdown();
}

  
void TreeTests::testTreeDelete()
{
	Stopwatch swatch("TreeTests::testTreeDelete");

	pb::uint64 tree2id;
	{
		OrmTransaction trans(conn);
		
		pb::uint64 treeid;
		
		::pb_orm_test::Tree tree;
		tree.set_version(1);
		tree.mutable_trunk()->set_name("trunk 1");
		tree.mutable_trunk()->add_branches()->add_leaves("leave 1");
		CPPUNIT_ASSERT(OrmMessageInsert(conn,tree,treeid));
		
		tree.Clear();
		tree.set_version(2);
		tree.mutable_trunk()->set_name("trunk 2");
		tree.mutable_trunk()->add_branches()->add_leaves("leave 2");
		CPPUNIT_ASSERT(OrmMessageInsert(conn,tree,tree2id));
		
		tree.Clear();
		tree.set_version(3);
		tree.mutable_trunk()->set_name("trunk 3");
		tree.mutable_trunk()->add_branches()->add_leaves("leave 3");
		CPPUNIT_ASSERT(OrmMessageInsert(conn,tree,treeid));
		
		trans.commit();
	}
	
	OrmResult result;
	pb::uint64 size;
	
	CPPUNIT_ASSERT(OrmMessageEnum(conn, pb_orm_test::Tree::descriptor(), result));
	if (result) {
		CPPUNIT_ASSERT(OrmGetSize(result,size));
		OrmFreeResult(result);
		CPPUNIT_ASSERT_MESSAGE("expected 3 rows in the Tree table.",size==3);
	}
	
	CPPUNIT_ASSERT(OrmMessageEnum(conn, pb_orm_test::Trunk::descriptor(), result));
	if (result) {
		CPPUNIT_ASSERT(OrmGetSize(result,size));
		OrmFreeResult(result);
		CPPUNIT_ASSERT_MESSAGE("expected 3 rows in the Trunk table.",size==3);
	}
	
	CPPUNIT_ASSERT(OrmMessageEnum(conn, pb_orm_test::Branch::descriptor(), result));
	if (result) {
		CPPUNIT_ASSERT(OrmGetSize(result,size));
		OrmFreeResult(result);
		CPPUNIT_ASSERT_MESSAGE("expected 3 rows in the Branch table.",size==3);
	}
	
	CPPUNIT_ASSERT(OrmMessageDelete(conn, pb_orm_test::Tree::descriptor(), tree2id));	
	CPPUNIT_ASSERT(OrmMessageEnum(conn, pb_orm_test::Tree::descriptor(), result));
	if (result) {
		CPPUNIT_ASSERT(OrmGetSize(result,size));
		OrmFreeResult(result);
		CPPUNIT_ASSERT_MESSAGE("expected 2 rows in the Tree table.",size==2);
	}
	
	CPPUNIT_ASSERT(OrmMessageEnum(conn, pb_orm_test::Trunk::descriptor(), result));
	if (result) {
		CPPUNIT_ASSERT(OrmGetSize(result,size));
		OrmFreeResult(result);
		CPPUNIT_ASSERT_MESSAGE("expected 2 rows in the Trunk table.",size==2);
	}
	
	CPPUNIT_ASSERT(OrmMessageEnum(conn, pb_orm_test::Branch::descriptor(), result));
	if (result) {
		CPPUNIT_ASSERT(OrmGetSize(result,size));
		OrmFreeResult(result);
		CPPUNIT_ASSERT_MESSAGE("expected 2 rows in the Branch table.",size==2);
	}
	
	// Get field descriptors from Tree,Trunk and Branch that we will need in
	// order to navigate the data in the tree.
	const pb::FieldDescriptor *trunkF =
	pb_orm_test::Tree::descriptor()->FindFieldByNumber(pb_orm_test::Tree::kTrunkFieldNumber);
	const pb::FieldDescriptor *branchesF = 
	pb_orm_test::Trunk::descriptor()->FindFieldByNumber(pb_orm_test::Trunk::kBranchesFieldNumber);
	const pb::FieldDescriptor *leavesF = 
	pb_orm_test::Branch::descriptor()->FindFieldByNumber(pb_orm_test::Branch::kLeavesFieldNumber);
	
	// TREE...
	pb::uint64 treeid;
	CPPUNIT_ASSERT(OrmMessageEnum(conn,pb_orm_test::Tree::descriptor(),result));
	if (result) {
		CPPUNIT_ASSERT_MESSAGE("expected to be able to select the first record in the tree table",OrmFirst(result));
		CPPUNIT_ASSERT_MESSAGE("expected to be able to select the second record in the tree table",OrmNext(result));
		CPPUNIT_ASSERT(OrmGetId(result,treeid));
		OrmFreeResult(result);
		
		CPPUNIT_ASSERT(trunkF!=NULL);
		
		pb::uint64 trunkid = 0;
		CPPUNIT_ASSERT(OrmFieldGetMessageId(conn, treeid, trunkF, trunkid));
		if (trunkid != 0) {
			
			CPPUNIT_ASSERT(OrmFieldEnumAllRepeatedValues(conn, trunkid, branchesF, result));
			if (result) {
				CPPUNIT_ASSERT(OrmFirst(result));
				pb::uint64 branchid;
				CPPUNIT_ASSERT(OrmGetId(result,branchid));
				OrmFreeResult(result);
				
				CPPUNIT_ASSERT(OrmFieldEnumAllRepeatedValues(conn, branchid, leavesF, result));
				if (result) {
					CPPUNIT_ASSERT(OrmFirst(result));
					pb::uint64 leaveid;
					CPPUNIT_ASSERT(OrmGetId(result,leaveid));
					
					std::string leave;
					CPPUNIT_ASSERT(OrmGetString(result, leave));
					
					OrmFreeResult(result);
					
					for (int i=0; i<10; ++i) {
						std::ostringstream leaveText;
						leaveText << "This is new leave " << i << " !";
						CPPUNIT_ASSERT(OrmFieldAddRepeatedString(conn, branchid, leavesF, leaveText.str().c_str(), leaveid));
					}
					
					
					CPPUNIT_ASSERT(OrmFieldEnumAllRepeatedValues(conn, branchid, leavesF, result));
					if (result) {
						
						for (bool ok=OrmFirst(result); ok; ok=OrmNext(result)) {
							pb::uint64 leaveid;
							CPPUNIT_ASSERT(OrmGetId(result,leaveid));
							
							CPPUNIT_ASSERT(OrmFieldDeleteRepeatedValue(conn, leavesF, leaveid));
						}
						OrmFreeResult(result);
					}
				}
			}
		}
	}
}

// All code under test must be linked into the Unit Test bundle
void TreeTests::testTreeCRUD()
{
	Stopwatch swatch("TreeTests::testTreeCRUD");

	CPPUNIT_ASSERT(treeInsert(conn,1000));
	
	::pb_orm_test::Tree tree;
	::pb_orm_test::Trunk trunk;
	::pb_orm_test::Branch branch;
	std::string leave;
	
	//
	// tree
	// 
	OrmResult tresult;
	CPPUNIT_ASSERT(OrmMessageEnum(conn, tree.descriptor(), tresult));
	CPPUNIT_ASSERT(OrmFirst(tresult));
	
	OrmContext context; 
	CPPUNIT_ASSERT(OrmGetMessage(tresult, tree, false, context));
	CPPUNIT_ASSERT(tree.version()==3);
	CPPUNIT_ASSERT(tree.has_trunk());
	pb::uint64 treeid;
	CPPUNIT_ASSERT(OrmGetId(tresult,treeid));
	OrmFreeResult(tresult);
	CPPUNIT_ASSERT(OrmMessageFind(conn, tree.descriptor(), treeid));
	
	tree.mutable_trunk()->set_name("Central Theme");
	tree.set_version(4);
	CPPUNIT_ASSERT(OrmMessageUpdate(context));
	
	OrmFreeContext(context);
	
	//
	// tree.trunk
	//
	const pb::FieldDescriptor *trunkF =
	tree.GetDescriptor()->FindFieldByNumber(::pb_orm_test::Tree::kTrunkFieldNumber);
	CPPUNIT_ASSERT(trunkF!=NULL);
	OrmResult fresult;
	CPPUNIT_ASSERT(OrmFieldSelectMessage(conn, treeid, trunkF, fresult));
	CPPUNIT_ASSERT(OrmGetMessage(fresult, trunk, false));
	pb::uint64 trunkid;
	CPPUNIT_ASSERT(OrmGetId(fresult,trunkid));
	OrmFreeResult(fresult);	
	
	
	//
	// tree.trunk.branches[x]
	//
	const pb::FieldDescriptor *branchF = 
	trunk.GetDescriptor()->FindFieldByNumber(::pb_orm_test::Trunk::kBranchesFieldNumber);
	CPPUNIT_ASSERT(branchF!=NULL);
	OrmResult qresult;
	CPPUNIT_ASSERT(OrmFieldEnumAllRepeatedValues(conn, trunkid, branchF, qresult));
	CPPUNIT_ASSERT(OrmFirst(qresult));
	CPPUNIT_ASSERT(OrmNext(qresult));
	CPPUNIT_ASSERT(OrmGetMessage(qresult,branch,false));
	pb::uint64 branchid = 1;
	CPPUNIT_ASSERT(OrmGetId(qresult,branchid));
	OrmFreeResult(qresult);
	
	
	//
	// tree.trunk.branches[x].leaves[y]
	//
	const pb::FieldDescriptor *leavesF = 
	branch.GetDescriptor()->FindFieldByNumber(::pb_orm_test::Branch::kLeavesFieldNumber);
	CPPUNIT_ASSERT(leavesF!=NULL);
	OrmResult lresult;
	CPPUNIT_ASSERT(OrmFieldEnumAllRepeatedValues(conn, branchid, leavesF, lresult));
	CPPUNIT_ASSERT(OrmFirst(lresult));
	CPPUNIT_ASSERT(OrmGetString(lresult,leave));
	OrmFreeResult(lresult);
	
	// Add
	pb::uint64 leaveid;
	CPPUNIT_ASSERT(OrmFieldAddRepeatedString(conn, branchid, leavesF, "a new leaf !", leaveid));
	
	CPPUNIT_ASSERT(OrmFieldSetRepeatedString(conn, leavesF, "a changed leaf !", leaveid));
	
	{
		OrmTransaction trans(conn);
		
		// Delete a message from a table.
		CPPUNIT_ASSERT(OrmMessageDelete(conn, tree.descriptor(), treeid));
		
		trans.commit();
	}
}

// All code under test must be linked into the Unit Test bundle
void TreeTests::testTreeReadRepeated()
{
	Stopwatch swatch("TreeTests::testTreeReadRepeated");

	CPPUNIT_ASSERT(treeInsert(conn,50));
	
	OrmResult dbresult;
	::pb_orm_test::Tree tree;
	OrmContext dbcontext; 
	CPPUNIT_ASSERT(OrmMessageEnum(conn, tree.descriptor(), dbresult));
	CPPUNIT_ASSERT(OrmFirst(dbresult));
	CPPUNIT_ASSERT(OrmGetMessage(dbresult,tree,true,dbcontext));
	OrmFreeResult(dbresult);
	OrmFreeContext(dbcontext);
	
}

// All code under test must be linked into the Unit Test bundle
void TreeTests::testTreeUpdateRepeated()
{
	const int BRANCHES = 7;

	Stopwatch swatch("TreeTests::testTreeUpdateRepeated");

	{
		Stopwatch swatch1("TreeTests::testTreeUpdateRepeated.1");
		
		CPPUNIT_ASSERT(treeInsert(conn,BRANCHES));
		
		swatch1.stop();
	}
	
	{	
		Stopwatch swatch2("TreeTests::testTreeUpdateRepeated.2");

		// Wrap a transaction around the OrmGetMessage/OrmUdateMessage combi
		OrmTransaction trans(conn); // makes it 10 times faster 30ms -> 3ms

		OrmResult dbresult;
		::pb_orm_test::Tree dbtree;
		OrmContext dbcontext;
		
		// retrieve the message from the database and make some changes then update
		CPPUNIT_ASSERT(OrmMessageEnum(conn, dbtree.descriptor(), dbresult));
		CPPUNIT_ASSERT(OrmFirst(dbresult));
		CPPUNIT_ASSERT(OrmGetMessage(dbresult,dbtree,true,dbcontext));
		OrmFreeResult(dbresult);
		
		dbtree.mutable_trunk()->mutable_branches(3)->set_leaves(4, "changing text around....");
		dbtree.mutable_trunk()->mutable_branches(3)->set_name("branch number 3");
		dbtree.mutable_trunk()->mutable_branches()->SwapElements(4, BRANCHES-1);
		dbtree.mutable_trunk()->mutable_branches()->RemoveLast();
		
		CPPUNIT_ASSERT(OrmMessageUpdate(dbcontext));
		OrmFreeContext(dbcontext);

		trans.commit();
		swatch2.stop();
	}
		
	{	
		Stopwatch swatch3("TreeTests::testTreeUpdateRepeated.3");
	
		::pb_orm_test::Tree tree;
		::pb_orm_test::Tree dbtree;
		OrmResult dbresult;
		
		CPPUNIT_ASSERT(OrmMessageEnum(conn, tree.descriptor(), dbresult));
		CPPUNIT_ASSERT(OrmFirst(dbresult));
		CPPUNIT_ASSERT(OrmGetMessage(dbresult, dbtree, true));
		OrmFreeResult(dbresult);
	
		CPPUNIT_ASSERT(dbtree.trunk().branches(3).name() == "branch number 3");

		swatch3.stop();
	}
	
	{
		Stopwatch swatch4("TreeTests::testTreeUpdateRepeated.4");
		
		// Wrap a transaction around the OrmGetMessage/OrmUdateMessage combi
		OrmTransaction trans(conn); // makes it 10 times faster 30ms -> 3ms

		::pb_orm_test::Tree dbtree;
		OrmResult dbresult;
		OrmContext dbcontext;
		
		// retrieve the message from the database again and make more changes.
		CPPUNIT_ASSERT(OrmMessageEnum(conn, dbtree.descriptor(), dbresult));
		CPPUNIT_ASSERT(OrmFirst(dbresult));
		CPPUNIT_ASSERT(OrmGetMessage(dbresult,dbtree,true,dbcontext));
		OrmFreeResult(dbresult);
		
		dbtree.mutable_trunk()->add_branches()->add_leaves("hi there !");
		
		for (int i=0; i<dbtree.mutable_trunk()->branches_size(); ++i) {
			std::ostringstream value;
			value << "branch @ index " << i;
			dbtree.mutable_trunk()->mutable_branches(i)->set_name(value.str());
		}
		dbtree.mutable_trunk()->mutable_branches()->RemoveLast();
		
		CPPUNIT_ASSERT(OrmMessageUpdate(dbcontext));
		
		OrmFreeContext(dbcontext);
		
		trans.commit();
		swatch4.stop();
	}
}

