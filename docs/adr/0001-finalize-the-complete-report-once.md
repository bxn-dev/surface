# Finalize the complete report once

`completed_at` records when all selected core and intelligence work has ended, not when core scanning alone ends, so a report has one authoritative completion point. A preflight failure receives dedicated serialized stage and kind values because it occurs before meaningful scan work and must not be misrepresented as a partial port-scan failure. These schema semantics are explicit now rather than deferred because changing serialized meanings after release would be harder and would preserve the current misleading classification.
