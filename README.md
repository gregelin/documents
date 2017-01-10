# VISTA Data Project

The Veterans Information System Technology Architecture (VISTA) is the integrated, comprehensive, longitudinal health information system of the U.S. Department of Veterans Affairs (VA). For the past thirty-five years, 131 VISTA systems have provided all clinical, financial, and administrative functions to support the operations of over 1200 VA hospitals and clinics throughout the United States. [ [VISTA Background](https://github.com/vistadataproject/documents/tree/master/Background/vista) ]


The VISTA Data Project is a new data-centric, model-driven approach to VA VISTA master data management and interfacing.  This is in contrast to the current code-centric approach to interfacing VISTA's data which relies on a byzantine array of thousands hard-coded opaque, brittle remote procedure calls (RPCs) which have accumulated over three decades - none of which are validated, documented, or maintained.  Such a code-centric approach does not provide a coherent, comprehensive, maintainable approach to master data management or interfacing to VISTA's data.

VISTA's master data model - the roadmap to all of VA's institutional, business process, and clinical know-how and data - has evolved organically over the past 35 years, but has not been surfaced and leveraged in computable form.  Now, for the first time, VISTA's data model will be comprehensively exposed, enriched, and operationalized as a single, secure, symmetric read-write, server-side interface to all VISTA data in all VISTA systems for external interfaces and integration. This data model uniformly bridges  all VISTA data models, allowing secure read-write access to all 131 VISTA systems enterprise-wide using a single Master VISTA Data Model (__MVDM__).

### Contrasting Interfacing Approaches
Current VISTA data interfaces wrap legacy MUMPS remote procedure calls (RPCs) within various mid-tier object models  __above the RPCs__ (figure below, left).  This dependency and encapsulation of legacy RPCs within the model not just fails to remediate, but propagates all the issues inherent to the MUMPS RPCs - most notably lack of testing, auditing and security. In contrast, the true, native, operational Master VISTA Data Model  __under the RPCs__ (figure below, right), not only provides a single, standardized, server-side interface to all VISTA data, but also remediates, documents, tests, audits, and secures all the legacy RPCs within the RPC Locker.

![vdp-model-above-below](https://github.com/vistadataproject/documents/blob/master/images/vdp-model-above-below-20170108e.png)

Examples of the mid-tier _RPC code wrapping frameworks_ include  Medical Domain Web Services (MDWS; C# wrapper), VISTA Integration Adapter (VIA; Java wrapper), VISTA Service Assembler (VSA; Java wrapper), and eHMP Resource Development Toolkit (RDK; Javascript wrapper). [[historical details](https://github.com/vistadataproject/documents/blob/master/README.md#current-mid-tier-mumps-rpc-code-wrapping-frameworks)]



