# Background

Over two years, the _VISTA Data Project_ ("the Project") is re-establishing the interface to VISTA used by CPRS ("CPRS RPC Interface") over a secure, symmetric, read-write data model, the Master VISTA Data Model ("MVDM"). The MVDM is implemented in Javascript and runs inside a node.js server. 

This move to a Javascipt-implemented, model-based system will deliver secure interfacing for existing VISTA clients like CPRS and enable rapid development and deployment of a whole new class of VISTA clients, unencumbered by legacy programming languages or data forms. 
    
In addition to the CPRS RPC Interface, the Project must re-establish _the Virtual Patient Record RPC_ ("VPR Interface"), which is not used by CPRS. The VPR Interface exports a patient's record from VISTA in XML form and supplies the majority of data to the JLV Client. Along with the CPRS RPC Interface, it establishes the functionality required of _MVDM_.

In its first year, the Project proved the effectiveness and practicality of a "master data model approach" for re-engineering VISTA. Representative parts of the CPRS RPC and VPR interfaces were re-established over a master data model running inside a node.js server. This re-constituted VISTA, "nodeVISTA", allowed CPRS to run unchanged.

In the second year, while the infrastructure of nodeVISTA must improve both in form and performance, a majority of the work will involve expanding MVDM to fully support the 1050 RPCs of the CPRS RPC Interface. As a result, expansion of RPC support by the MVDM will be a clear measure of progress.

RPC Breakdown: [full details](http://vistadataproject.info/artifacts/cprsRPCBreakdown/bdStart)

# 5 Tracks

Year 2 work breaks into __five tracks__:

  1. __Clinical RPCs__ supported in MVDM
  2. __Non Clinical RPCs__ supported in MVDM
  3. __Security__ including Authentication, Access Control and Auditing
  4. __Infrastructure__ required for MVDM and nodeVISTA
  5. Integrated, easy to install __Demonstration__

## Clinical RPCs 

Clinical RPCs effect a patient's record.

Note: for details, [see](http://vistadataproject.info/artifacts/cprsRPCBreakdown/bdClinical).

CPRS uses these RPCs to update and enhance a Patient's record and RPCs that update (sometimes termed "write back RPCs") are much more complicated than RPCs which just read data. 
    
Specifically, these Clinical RPCs encompass _CPOE_ (Order Management) and user controlled and often stateful data entry about a patient's health (Problem, Allergy, Immunization, Documents ...). 
    
__Computerized Physician Order Entry (CPOE) is the key function offered by VISTA__ and migrating it to MVDM will take a substantial part of the Project's efforts going forward. In particular, some aspects of Order management don't involve CPRS directly but must be addressed to develop and test CPRS interactions. In addition, the test VISTA system used in the project was not pre-configured for Order Entry and as a result, developers will need to perform basic system configuration in order to develop and test VISTA ordering in a master model.

Year 1 of VDP proved that even the hardest of Clinical RPCs could be supported over an MVDM. In doing so, a set of _MVDM Utilities_ were developed that support reading, writing and checking any VISTA class or property. 

Year 2 will reuse these utilities to provide MVDM support for all Clinical RPCs.

## Non Clinical RPCs

Non-Clinical RPCs deal with user preferences ("what is a user's preferred size of vital screen?"), system settings ("web site of system") and, in particular, a large volume of meta-data that drives the choices a user can make when ordering and documenting as she cares for a patient ("list of drugs you can order", "document types you can write").

Note: for details, [see](http://vistadataproject.info/artifacts/cprsRPCBreakdown/bdNon_Clinical).
    
While large in number, these RPCs are substantively __simpler than Clinical RPCs__. They mainly READ data as CPRS doesn't change non clinical data other than user preferences.

Non Clinical RPCs break into three groups:
  * One third involve information retrieval about a User and her preferences. Many of these rely on VISTA's _Parameter Mechanism_ which will have to supported in Javascript.
  * A half involve "Knowledge data" such as "lists of document titles", "lists of drugs" and specific information about lab tests. This user and patient independent _meta data_ largely drives the system
  * The remainder implement utilities for calculating dates and provide access to system-wide configuration data

## Security

Security is involves _Authentication_ (is this Dr Richards?), _Access Control_ (should Dr Richards be able to do this?) and _Auditing_ (what did Dr Richards do?). 

MVDM is designed to run under any authentication policy adopted by VA including the current access-verify and old CAPRI methods deployed in VISTA. During year 1, Authentication RPCs were fully exercised and leveraged to support user identity for nodeVISTA. This authentication may need to be enhanced in Year 2 should VA accelerate the deployment of a new SAML-based mechanism.

However, the main security focus for VDP is Access Control and Authentication. In Year 1, access control policies were supported in the MVDM and auditing was enabled through the MVDM change event mechanism.

In Year 2, more example Access Control policies will be added to show how MVDM based access control exceeds VISTA's current "menu-based" approach. A formal audit store will be established to show how all VISTA changes may be stored in an easy to maintain and analyze format.

Though valuable, these efforts will represent a fraction of the work required for the first two tracks.

## Infrastructure

Five pieces of infrastructure supported the re-engineering of VISTA undertaken in year 1 of VDP:

  1. a multi-process node server with support for the RPC broker protocol and authentication (_rpcServer_). Multi-process support leveraged the EWD node modules.
  2. a set of utilities for reliably writing data from MVDM Javascript to MUMPS-based VISTA (_MVDM Write Framework_)
  3. a set of utilities for invoking MUMPS implemented RPCs either in-process or over a network and way to replay sequences of RPC calls (_RPC Session Runner_)
  4. a set of utilities for reliably query data into MVDM Javascript from MUMPS-based VISTA (_MVDM Query Framework_). This framework relied on the open source FMQL plugin.
  5. a Vagrant Virtual Machine (VM) packaging of an open source VISTA ("nodeVISTA Vagrant"). This packaging was derived from OSEHRA VISTA's packaging.
  6. utilities for analyzing the contents of full VISTA ("prodclones") 
  
All six will be improved in year 2 both to increase ease of use and efficiency and for features required as RPC coverage in MVDM expands. 

## Demonstration

Demonstrability is key for any practical project. The various pieces being engineered must come together to tell a story.

Year 1 delivered a fully integrated demo with CPRS working seemlessly over an MVDM-enabled VISTA. In addition, there was a Web client ("MVDM Management Client") that showed all of the activity involved as CPRS interacted with this re-engineered VISTA.

In Year 2, the demo will by nature expand its scope just through the underlying expansion of MVDM. In addition, two new clients will be developed, one to showcase auditing and another to demonstrate how easy it is to build new clients directly over MVDM. The _VDP_ website will have complete (generated) developer documentation.

# Outline of Schedule

Track | Q1 | Q2 | Q3 | Q4
--- | --- | --- | --- | ---
__Clinical RPCs__ (Track 1) | CPOE outline and basic prototyping | CPOE Delivery 1 | CPOE Delivery 2, Other Clinical Domains 1 | CPOE Final, Other Clinical Domains 2
__Non Clinical RPCs__ (Track 2) | Outline and basic prototyping | NC RPC Delivery | - | -
__Security__ (Track 3) | PIKS analysis upgrade based on Track 2 Outlines | - | Security Prototype Upgrade | -
__Infrastructure__ (Track 4) | Query Framework Upgrade, Parameter Service, RPC Server Upgrade 1, MVDM Service Server 1, Dialog Test Utilities | MVDM Write Framework Upgrade | nodeVISTA Vagrant Upgrade | nodeVISTA Vagrant final
__Demonstration__ (Track 5) | Demo 2.1 | Demo 2.2 | Demo 2.3 | Demo 2.4

  * CPOE (Orders) will frame much of the work for year 2. To add MVDM support for VISTA orders will force infrastructure upgrades,  significant meta-data addition to the test system and analysis of non-CPRS driven data flows
  * Track 2 may not end in Q2. If it does go on then work on clinical domains beyond CPOE will be impacted
  * Infrastructure will be upgraded as needed for Tracks 1 and 2. Only distinct pieces of work are called out explicitly above
  * Demonstration will be upgraded as functionality is added in Tracks 1 and 2
  
# Relationship to Year 1 Deliverables and CLINs

TBD - map back to year 1 deliverables for easy reporting.
