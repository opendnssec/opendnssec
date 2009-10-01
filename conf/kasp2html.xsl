<?xml version="1.0" encoding="UTF-8"?>

<!--$Id$ -->

<!--

 Copyright (c) 2009 .SE (The Internet Infrastructure Foundation).
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:
 1. Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

 THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-->


<xsl:stylesheet version="1.0"
	xml:lang="en"
	xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	xmlns="http://www.w3.org/TR/xhtml1/strict">

	<xsl:output method="xml" indent="yes" encoding="UTF-8"/>

	<xsl:template match="KASP">
		<html>
		 <head>
			<title>KASP</title>
			<style type="text/css">
				<xsl:text>
					td.tag   { background-color: #dddddd; width: 5cm; }
					td.value { width: 10cm; }
				</xsl:text>
			</style>
		 </head>
		 <body>
			<h1><xsl:text>KASP: Key and Signature Policy</xsl:text></h1>
			<xsl:apply-templates/>
		 </body>
		</html>
	</xsl:template>

	<xsl:template match="Policy">
		<h2><xsl:text>Policy: </xsl:text><xsl:value-of select="@name"/></h2>
		<p><small><xsl:value-of select="Description"/></small></p>
		<xsl:apply-templates/>
	</xsl:template>

	<xsl:template match="Description">
	</xsl:template>

	<xsl:template match="Signatures">
		<h3><xsl:text>Signatures</xsl:text></h3>
		<table>
			<tr>
				<td class="tag"><xsl:text>Resign</xsl:text></td>
				<td class="value"><xsl:value-of select="Resign"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Refresh</xsl:text></td>
				<td class="value"><xsl:value-of select="Refresh"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Validity</xsl:text></td>
				<td class="value"><xsl:value-of select="Validity/Default"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Validity NSEC/NSEC3</xsl:text></td>
				<td class="value"><xsl:value-of select="Validity/Denial"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Jitter</xsl:text></td>
				<td class="value"><xsl:value-of select="Jitter"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Inception Offset</xsl:text></td>
				<td class="value"><xsl:value-of select="InceptionOffset"/></td>
			</tr>
	   </table>
	</xsl:template>

	<xsl:template match="Denial">
		<h3><xsl:text>Denial of Existence</xsl:text></h3>
		<xsl:apply-templates/>
	</xsl:template>

	<xsl:template match="Denial/NSEC">
		<table>
			<tr>
				<td class="tag"><xsl:text>Method</xsl:text></td>
				<td class="value"><xsl:text>NSEC</xsl:text></td>
			</tr>
	   </table>
	</xsl:template>

	<xsl:template match="Denial/NSEC3">
		<table>
			<tr>
				<td class="tag"><xsl:text>Method</xsl:text></td>
				<td class="value"><xsl:text>NSEC3</xsl:text></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Opt-Out</xsl:text></td>
				<td class="value">
				  <xsl:call-template name="yesno">
            <xsl:with-param name="argument" select="OptOut"/>
          </xsl:call-template>
				</td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Resalt</xsl:text></td>
				<td class="value"><xsl:value-of select="Resalt"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Hash Algorithm</xsl:text></td>
				<td class="value"><xsl:value-of select="Hash/Algorithm"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Hash Iterations</xsl:text></td>
				<td class="value"><xsl:value-of select="Hash/Iterations"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Hash Salt Length</xsl:text></td>
				<td class="value"><xsl:value-of select="Hash/Salt/@length"/></td>
			</tr>
		</table>
	</xsl:template>

	<xsl:template match="Keys">
		<h3><xsl:text>Key Parameters</xsl:text></h3>
		<table>
			<tr>
				<td class="tag"><xsl:text>TTL</xsl:text></td>
				<td class="value"><xsl:value-of select="TTL"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Retire Safety</xsl:text></td>
				<td class="value"><xsl:value-of select="RetireSafety"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Publish Safety</xsl:text></td>
				<td class="value"><xsl:value-of select="PublishSafety"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Share Keys?</xsl:text></td>
				<td class="value">
				  <xsl:call-template name="yesno">
            <xsl:with-param name="argument" select="ShareKeys"/>
          </xsl:call-template>
				</td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>Purge dead keys after</xsl:text></td>
			  <td class="value"><xsl:value-of select="Purge"/></td>
			</tr>
			<tr>
				<td colspan="2"><b><xsl:text>KSK</xsl:text></b></td>
			</tr>		
			<xsl:apply-templates select="KSK"/>
			<tr>
				<td colspan="2"><b><xsl:text>ZSK</xsl:text></b></td>
			</tr>		
			<xsl:apply-templates select="ZSK"/>
		 </table>
	</xsl:template>

	<xsl:template match="Keys/KSK">
		<xsl:call-template name="anykey"/>
		<tr>
			<td class="tag"><xsl:text>Use RFC5011?</xsl:text></td>
			<td class="value">
			  <xsl:call-template name="yesno">
          <xsl:with-param name="argument" select="RFC5011"/>
        </xsl:call-template>
			</td>
		</tr>
	</xsl:template>

	<xsl:template match="Keys/ZSK">
		<xsl:call-template name="anykey"/>
	</xsl:template>

	<xsl:template match="Zone">
		<h3><xsl:text>Zone Parameters</xsl:text></h3>
		<table>
			<tr>
				<td class="tag"><xsl:text>Propagation Delay</xsl:text></td>
				<td class="value"><xsl:value-of select="PropagationDelay"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>SOA TTL</xsl:text></td>
				<td class="value"><xsl:value-of select="SOA/TTL"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>SOA Minimum</xsl:text></td>
				<td class="value"><xsl:value-of select="SOA/Minimum"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>SOA Serial Format</xsl:text></td>
				<td class="value"><xsl:apply-templates select="SOA/Serial"/></td>
			</tr>
		 </table>
	</xsl:template>

	<xsl:template match="Parent">
		<h3><xsl:text>Parent Parameters</xsl:text></h3>
		<table>
			<tr>
				<td class="tag"><xsl:text>Propagation Delay</xsl:text></td>
				<td class="value"><xsl:value-of select="PropagationDelay"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>DS TTL</xsl:text></td>
				<td class="value"><xsl:value-of select="DS/TTL"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>SOA TTL</xsl:text></td>
				<td class="value"><xsl:value-of select="SOA/TTL"/></td>
			</tr>
			<tr>
				<td class="tag"><xsl:text>SOA Minimum</xsl:text></td>
				<td class="value"><xsl:value-of select="SOA/Minimum"/></td>
			</tr>
		 </table>
	</xsl:template>

	<xsl:template match="Audit">
	</xsl:template>
	
	<xsl:template match="Keys/*/Algorithm">
		<xsl:choose>
			<xsl:when test=". = 1">
				<xsl:text>RSA/MD5</xsl:text>						
			</xsl:when>
			<xsl:when test=". = 3">
				<xsl:text>DSA/SHA1</xsl:text>						
			</xsl:when>
			<xsl:when test=". = 5">
				<xsl:text>RSA/SHA-1</xsl:text>						
			</xsl:when>
			<xsl:when test=". = 6">
				<xsl:text>DSA-NSEC3-SHA1</xsl:text>						
			</xsl:when>
			<xsl:when test=". = 7">
				<xsl:text>RSASHA1-NSEC3-SHA1</xsl:text>						
			</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="."/>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:template>

	<xsl:template match="SOA/Serial">
		<xsl:choose>
			<xsl:when test=". = 'counter'">
				<xsl:text>Counter</xsl:text>						
			</xsl:when>
			<xsl:when test=". = 'unixtime'">
				<xsl:text>UNIX Timestamp (as 32-bit Unsigned Integer)</xsl:text>						
			</xsl:when>
			<xsl:when test=". = 'datecounter'">
				<xsl:text>YYYYMMDDnn (Date + 2-Digit-Counter)</xsl:text>						
			</xsl:when>
			<xsl:when test=". = 'keep'">
				<xsl:text>Keep Serial from the Unsigned Zone</xsl:text>						
			</xsl:when>
			<xsl:otherwise>
				<xsl:value-of select="."/>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:template>

	<xsl:template name="yesno">
	  <xsl:param name="argument" select="N/A"/>
		<xsl:choose>
			<xsl:when test="$argument">
				<xsl:text>Yes</xsl:text>						
			</xsl:when>
			<xsl:otherwise>
				<xsl:text>No</xsl:text>
			</xsl:otherwise>
		</xsl:choose>
	</xsl:template>

	<xsl:template name="anykey">
		<tr>
			<td class="tag"><xsl:text>Algorithm</xsl:text></td>
			<td class="value">
				<xsl:apply-templates select="Algorithm"/>
				<xsl:text> / </xsl:text>
				<xsl:value-of select="Algorithm/@length"/>
			</td>
		</tr>
		<tr>
			<td class="tag"><xsl:text>Lifetime</xsl:text></td>
			<td class="value"><xsl:value-of select="Lifetime"/></td>
		</tr>
		<tr>
			<td class="tag"><xsl:text>Repository</xsl:text></td>
			<td class="value"><xsl:value-of select="Repository"/></td>
		</tr>
		<tr>
			<td class="tag"><xsl:text>Number of Standby Keys</xsl:text></td>
			<td class="value"><xsl:value-of select="Standby"/></td>
		</tr>
	</xsl:template>

</xsl:stylesheet>
