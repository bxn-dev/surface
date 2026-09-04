# Surface

Surface describes an authorized, bounded security scan and the report that preserves its evidence and outcome.

## Language

**Scan lifecycle**:
The progression of an authorized scan from preflight through selected checks to one terminal report outcome.

**Complete report**:
A report after all selected core and intelligence work has ended and its final status, findings, exposure, and completion time have been recorded.
_Avoid_: Core-complete report

**Preflight failure**:
A terminal outcome produced before meaningful scan work begins because the requested scan cannot be executed as configured.
_Avoid_: Port failure, partial scan

**Intelligence source**:
One selected origin of passive, non-target-expanding evidence, whether supplied by the operator or collected remotely.
_Avoid_: Provider, target source

**Partial evidence**:
Useful evidence retained from an intelligence source that did not complete every selected operation.
_Avoid_: Failed evidence, complete evidence

**SSH posture**:
Bounded evidence inferred from an SSH identification exchange and client-first algorithm intersections without completing key exchange.
_Avoid_: Negotiated SSH configuration, server preference

**Partial SSH posture**:
SSH posture containing some algorithm selections but not every selection required for a complete inference; it cannot support a legacy-algorithm finding.
_Avoid_: Complete SSH posture, negotiated algorithms
