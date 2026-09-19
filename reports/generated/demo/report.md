# IIS Purple Lab investigation

Dataset origin: handcrafted\-fixture.

Observed 70 records and 16 alerts (including component alerts, not independent attack counts).
Fixture replay does not establish native Windows execution. Missing sources remain unknown.

## Findings

- IPL\-001 (high): Successful access violates tenant, sharing and administrator policy\.. [e-c81d582516c96afacff0e20e](report.html#e-c81d582516c96afacff0e20e)
- IPL\-001 (high): Successful access violates tenant, sharing and administrator policy\.. [e-1a99c365bc06037f51882aef](report.html#e-1a99c365bc06037f51882aef)
- IPL\-002 (medium): An IIS worker launched an interpreter\. Legitimate legacy exports remain an alternative\.. [e-db60ba62c67ba3bc399bbafb](report.html#e-db60ba62c67ba3bc399bbafb)
- IPL\-002 (medium): An IIS worker launched an interpreter\. Legitimate legacy exports remain an alternative\.. [e-a9dda72ad80a573c2d9eb5db](report.html#e-a9dda72ad80a573c2d9eb5db)
- IPL\-002 (medium): An IIS worker launched an interpreter\. Legitimate legacy exports remain an alternative\.. [e-6bd3dc9d03a346ea4f9686c6](report.html#e-6bd3dc9d03a346ea4f9686c6)
- IPL\-002 (medium): An IIS worker launched an interpreter\. Legitimate legacy exports remain an alternative\.. [e-5f301bf3435f8cc37f8cee2c](report.html#e-5f301bf3435f8cc37f8cee2c)
- IPL\-002 (medium): An IIS worker launched an interpreter\. Legitimate legacy exports remain an alternative\.. [e-c74ce06592427b10b577b77f](report.html#e-c74ce06592427b10b577b77f)
- IPL\-003 (medium): Observed ProcessGuid ancestry connects identity/host discovery to IIS; intent is inferred\.. [e-0050ae31c1536edf2521d3b8](report.html#e-0050ae31c1536edf2521d3b8), [e-6bd3dc9d03a346ea4f9686c6](report.html#e-6bd3dc9d03a346ea4f9686c6), [e-834fe0244e021a3ddf4e414a](report.html#e-834fe0244e021a3ddf4e414a)
- IPL\-003 (medium): Observed ProcessGuid ancestry connects identity/host discovery to IIS; intent is inferred\.. [e-44c6350abc3a5c895571f05d](report.html#e-44c6350abc3a5c895571f05d), [e-7cc941d7f2a9908b0ebabd3f](report.html#e-7cc941d7f2a9908b0ebabd3f), [e-db60ba62c67ba3bc399bbafb](report.html#e-db60ba62c67ba3bc399bbafb)
- IPL\-004 (medium): An interpreter descendant wrote under a protected application data root; no read is established\.. [e-0f648897a75aefa4f1b25f32](report.html#e-0f648897a75aefa4f1b25f32), [e-44c6350abc3a5c895571f05d](report.html#e-44c6350abc3a5c895571f05d), [e-db60ba62c67ba3bc399bbafb](report.html#e-db60ba62c67ba3bc399bbafb)
- IPL\-004 (medium): An interpreter descendant wrote under a protected application data root; no read is established\.. [e-0050ae31c1536edf2521d3b8](report.html#e-0050ae31c1536edf2521d3b8), [e-34f6707f04d6e8b98397694f](report.html#e-34f6707f04d6e8b98397694f), [e-6bd3dc9d03a346ea4f9686c6](report.html#e-6bd3dc9d03a346ea4f9686c6)
- IPL\-005 (medium): Connection outside the configured report destination policy; connection alone does not establish transfer\.. [e-44c6350abc3a5c895571f05d](report.html#e-44c6350abc3a5c895571f05d), [e-686c868170dd18e201c7e252](report.html#e-686c868170dd18e201c7e252), [e-db60ba62c67ba3bc399bbafb](report.html#e-db60ba62c67ba3bc399bbafb)
- IPL\-005 (medium): Connection outside the configured report destination policy; connection alone does not establish transfer\.. [e-0050ae31c1536edf2521d3b8](report.html#e-0050ae31c1536edf2521d3b8), [e-6bd3dc9d03a346ea4f9686c6](report.html#e-6bd3dc9d03a346ea4f9686c6), [e-77641da7be8f52fff0b3b730](report.html#e-77641da7be8f52fff0b3b730)
- IPL\-006 (high): Shell\-control syntax in an accepted report request and independently observed endpoint execution share a high\-confidence launch link\.. [e-0f648897a75aefa4f1b25f32](report.html#e-0f648897a75aefa4f1b25f32), [e-44c6350abc3a5c895571f05d](report.html#e-44c6350abc3a5c895571f05d), [e-686c868170dd18e201c7e252](report.html#e-686c868170dd18e201c7e252), [e-73632973018b03632f84775d](report.html#e-73632973018b03632f84775d), [e-7cc941d7f2a9908b0ebabd3f](report.html#e-7cc941d7f2a9908b0ebabd3f), [e-9e25cbbc5c09f242ea2fce79](report.html#e-9e25cbbc5c09f242ea2fce79), [e-db60ba62c67ba3bc399bbafb](report.html#e-db60ba62c67ba3bc399bbafb)
- IPL\-006 (high): Shell\-control syntax in an accepted report request and independently observed endpoint execution share a high\-confidence launch link\.. [e-5a071b4a17a06082bee6d42a](report.html#e-5a071b4a17a06082bee6d42a), [e-a9dda72ad80a573c2d9eb5db](report.html#e-a9dda72ad80a573c2d9eb5db), [e-d80ff433f8159581ada2f1a8](report.html#e-d80ff433f8159581ada2f1a8), [e-edfbccc54f67737793b39083](report.html#e-edfbccc54f67737793b39083)
- IPL\-006 (high): Shell\-control syntax in an accepted report request and independently observed endpoint execution share a high\-confidence launch link\.. [e-0050ae31c1536edf2521d3b8](report.html#e-0050ae31c1536edf2521d3b8), [e-34f6707f04d6e8b98397694f](report.html#e-34f6707f04d6e8b98397694f), [e-6bd3dc9d03a346ea4f9686c6](report.html#e-6bd3dc9d03a346ea4f9686c6), [e-77641da7be8f52fff0b3b730](report.html#e-77641da7be8f52fff0b3b730), [e-7d161008b6034f5a503d3c9a](report.html#e-7d161008b6034f5a503d3c9a), [e-834fe0244e021a3ddf4e414a](report.html#e-834fe0244e021a3ddf4e414a), [e-c487aab91defb92d16a9369e](report.html#e-c487aab91defb92d16a9369e)

## UTC timeline

| Event time | Source | Observation | Evidence |
| --- | --- | --- | --- |
| 2026\-08\-21T10:00:04\.000000Z | sysmon | C:\\Windows\\System32\\inetsrv\\w3wp\.exe | [e-185eb09de78a344c4fff46d6](report.html#e-185eb09de78a344c4fff46d6) |
| 2026\-08\-21T10:00:10\.000000Z | application | report\_request | [e-1f404b39e40db826b49f4f91](report.html#e-1f404b39e40db826b49f4f91) |
| 2026\-08\-21T10:00:10\.000000Z | iis | /api/reports | [e-4c8f18055006d27781ebf329](report.html#e-4c8f18055006d27781ebf329) |
| 2026\-08\-21T10:00:10\.020000Z | sysmon | C:\\IISPurpleLab\\app\\IisPurpleLab\.exe | [e-35e0eee8115d291314aabc22](report.html#e-35e0eee8115d291314aabc22) |
| 2026\-08\-21T10:00:10\.080000Z | application | process\_launch | [e-42b620654875aa4d4505e92b](report.html#e-42b620654875aa4d4505e92b) |
| 2026\-08\-21T10:00:26\.000000Z | sysmon | C:\\Windows\\System32\\inetsrv\\w3wp\.exe | [e-eec27cb386cec4c90aebd6bc](report.html#e-eec27cb386cec4c90aebd6bc) |
| 2026\-08\-21T10:00:30\.000000Z | iis | /api/reports | [e-07e4724f0f3a830b0d635c4a](report.html#e-07e4724f0f3a830b0d635c4a) |
| 2026\-08\-21T10:00:30\.000000Z | application | report\_request | [e-0a2a122e7f916bd1617df463](report.html#e-0a2a122e7f916bd1617df463) |
| 2026\-08\-21T10:00:30\.000000Z | iis | /api/reports | [e-9a77404fb53857e308fe9783](report.html#e-9a77404fb53857e308fe9783) |
| 2026\-08\-21T10:00:30\.000000Z | application | report\_request | [e-f01465b9baeddde13c3bd2f2](report.html#e-f01465b9baeddde13c3bd2f2) |
| 2026\-08\-21T10:00:30\.020000Z | sysmon | C:\\IISPurpleLab\\app\\IisPurpleLab\.exe | [e-6cd4fcb0c6387f3b467b1761](report.html#e-6cd4fcb0c6387f3b467b1761) |
| 2026\-08\-21T10:00:30\.020000Z | sysmon | C:\\IISPurpleLab\\app\\IisPurpleLab\.exe | [e-9f2d769923dfa34d325facb4](report.html#e-9f2d769923dfa34d325facb4) |
| 2026\-08\-21T10:00:30\.080000Z | application | process\_launch | [e-8a333ccd5d8c6647046ccac8](report.html#e-8a333ccd5d8c6647046ccac8) |
| 2026\-08\-21T10:00:30\.080000Z | application | process\_launch | [e-ff73efda0acec908a41a17b7](report.html#e-ff73efda0acec908a41a17b7) |
| 2026\-08\-21T10:00:50\.000000Z | iis | /api/tickets/ticket\-2762 | [e-5176c6a62a69bb9f1b56b759](report.html#e-5176c6a62a69bb9f1b56b759) |
| 2026\-08\-21T10:00:50\.000000Z | application | ticket\_access | [e-b7ff1ce1ef060e38f5f50f1e](report.html#e-b7ff1ce1ef060e38f5f50f1e) |
| 2026\-08\-21T10:01:10\.000000Z | application | ticket\_access | [e-b85af6cd5c6a13f1841fdff7](report.html#e-b85af6cd5c6a13f1841fdff7) |
| 2026\-08\-21T10:01:10\.000000Z | iis | /api/tickets/ticket\-5101 | [e-d7fd477bb97d5673b1088326](report.html#e-d7fd477bb97d5673b1088326) |
| 2026\-08\-21T10:01:24\.000000Z | sysmon | C:\\Windows\\System32\\inetsrv\\w3wp\.exe | [e-cc3b87cc43839ebd40c433db](report.html#e-cc3b87cc43839ebd40c433db) |
| 2026\-08\-21T10:01:30\.000000Z | application | report\_request | [e-416b98f188e9e4bdc1bb16e1](report.html#e-416b98f188e9e4bdc1bb16e1) |
| 2026\-08\-21T10:01:30\.000000Z | iis | /api/reports | [e-56a04d90b786a37eaf45dac7](report.html#e-56a04d90b786a37eaf45dac7) |
| 2026\-08\-21T10:01:30\.020000Z | sysmon | C:\\Windows\\System32\\cmd\.exe | [e-5f301bf3435f8cc37f8cee2c](report.html#e-5f301bf3435f8cc37f8cee2c) |
| 2026\-08\-21T10:01:30\.080000Z | application | process\_launch | [e-14793a1aa7fcdf7e45f0686c](report.html#e-14793a1aa7fcdf7e45f0686c) |
| 2026\-08\-21T10:02:03\.000000Z | sysmon | C:\\Windows\\System32\\inetsrv\\w3wp\.exe | [e-44c6350abc3a5c895571f05d](report.html#e-44c6350abc3a5c895571f05d) |
| 2026\-08\-21T10:02:10\.000000Z | application | report\_request | [e-73632973018b03632f84775d](report.html#e-73632973018b03632f84775d) |
| 2026\-08\-21T10:02:10\.000000Z | iis | /api/reports | [e-9c811d24f1d388492e1afd09](report.html#e-9c811d24f1d388492e1afd09) |
| 2026\-08\-21T10:02:10\.020000Z | sysmon | C:\\Windows\\System32\\cmd\.exe | [e-db60ba62c67ba3bc399bbafb](report.html#e-db60ba62c67ba3bc399bbafb) |
| 2026\-08\-21T10:02:10\.080000Z | application | process\_launch | [e-9e25cbbc5c09f242ea2fce79](report.html#e-9e25cbbc5c09f242ea2fce79) |
| 2026\-08\-21T10:02:10\.300000Z | sysmon | C:\\Windows\\System32\\whoami\.exe | [e-7cc941d7f2a9908b0ebabd3f](report.html#e-7cc941d7f2a9908b0ebabd3f) |
| 2026\-08\-21T10:02:10\.400000Z | sysmon | C:\\Windows\\System32\\cmd\.exe | [e-0f648897a75aefa4f1b25f32](report.html#e-0f648897a75aefa4f1b25f32) |
| 2026\-08\-21T10:02:10\.500000Z | sysmon | C:\\Windows\\System32\\cmd\.exe | [e-686c868170dd18e201c7e252](report.html#e-686c868170dd18e201c7e252) |
| 2026\-08\-21T10:02:30\.000000Z | application | attachment\_access | [e-1a99c365bc06037f51882aef](report.html#e-1a99c365bc06037f51882aef) |
| 2026\-08\-21T10:02:30\.000000Z | iis | /api/tickets/ticket\-6154 | [e-f40b1c5df71e6a8a2742e89e](report.html#e-f40b1c5df71e6a8a2742e89e) |
| 2026\-08\-21T10:02:50\.000000Z | iis | /api/tickets/ticket\-2200 | [e-1dd611d56ac82158b161a50b](report.html#e-1dd611d56ac82158b161a50b) |
| 2026\-08\-21T10:02:50\.000000Z | application | ticket\_access | [e-c81d582516c96afacff0e20e](report.html#e-c81d582516c96afacff0e20e) |
| 2026\-08\-21T10:03:10\.000000Z | iis | /api/tickets/ticket\-3243 | [e-c4a6baa53e98af70a39a1424](report.html#e-c4a6baa53e98af70a39a1424) |
| 2026\-08\-21T10:03:10\.000000Z | application | ticket\_access | [e-d0339aa429d7baabaeb729b6](report.html#e-d0339aa429d7baabaeb729b6) |
| 2026\-08\-21T10:03:27\.000000Z | sysmon | C:\\Windows\\System32\\inetsrv\\w3wp\.exe | [e-74b72b2d34528b1833daf021](report.html#e-74b72b2d34528b1833daf021) |
| 2026\-08\-21T10:03:30\.000000Z | application | report\_request | [e-6d7d297fb8b6132fa37974db](report.html#e-6d7d297fb8b6132fa37974db) |
| 2026\-08\-21T10:03:30\.000000Z | iis | /api/reports | [e-90cbc301329c271fbb5c8c88](report.html#e-90cbc301329c271fbb5c8c88) |
| 2026\-08\-21T10:03:30\.020000Z | sysmon | C:\\IISPurpleLab\\app\\IisPurpleLab\.exe | [e-eacae92f57e42be7251de81e](report.html#e-eacae92f57e42be7251de81e) |
| 2026\-08\-21T10:03:30\.080000Z | application | process\_launch | [e-63d0fa5936c98eb5ab5f7dac](report.html#e-63d0fa5936c98eb5ab5f7dac) |
| 2026\-08\-21T10:03:42\.000000Z | sysmon | C:\\Windows\\System32\\inetsrv\\w3wp\.exe | [e-3957f8d0de39a5358bda165c](report.html#e-3957f8d0de39a5358bda165c) |
| 2026\-08\-21T10:03:50\.000000Z | iis | /api/reports | [e-32cbd13744b19acb1013e73a](report.html#e-32cbd13744b19acb1013e73a) |
| 2026\-08\-21T10:03:50\.000000Z | application | report\_request | [e-d2a6a42f62ae8a7efae5223e](report.html#e-d2a6a42f62ae8a7efae5223e) |
| 2026\-08\-21T10:03:50\.020000Z | sysmon | C:\\IISPurpleLab\\app\\IisPurpleLab\.exe | [e-58d588efa579923ed36c1108](report.html#e-58d588efa579923ed36c1108) |
| 2026\-08\-21T10:03:50\.080000Z | application | process\_launch | [e-7f85ba75f653c7bc7e309c12](report.html#e-7f85ba75f653c7bc7e309c12) |
| 2026\-08\-21T10:04:10\.000000Z | application | ticket\_access | [e-07312c649b862e74bb319855](report.html#e-07312c649b862e74bb319855) |
| 2026\-08\-21T10:04:10\.000000Z | iis | /api/tickets/ticket\-2807 | [e-be4d7de383eae0942c4bc64b](report.html#e-be4d7de383eae0942c4bc64b) |
| 2026\-08\-21T10:04:24\.000000Z | sysmon | C:\\Windows\\System32\\inetsrv\\w3wp\.exe | [e-7e9c681ebf813d891b3ccf25](report.html#e-7e9c681ebf813d891b3ccf25) |
| 2026\-08\-21T10:04:30\.000000Z | iis | /api/reports | [e-b0ea07b3504f7dd4ac8b0f26](report.html#e-b0ea07b3504f7dd4ac8b0f26) |
| 2026\-08\-21T10:04:30\.020000Z | sysmon | C:\\Windows\\System32\\cmd\.exe | [e-c74ce06592427b10b577b77f](report.html#e-c74ce06592427b10b577b77f) |
| 2026\-08\-21T10:04:50\.000000Z | iis | /api/tickets/ticket\-6210 | [e-d911910d33e8cd6c7bc2996a](report.html#e-d911910d33e8cd6c7bc2996a) |
| 2026\-08\-21T10:05:10\.000000Z | application | ticket\_access | [e-2cf26d907fd1a6d5fbb41d04](report.html#e-2cf26d907fd1a6d5fbb41d04) |
| 2026\-08\-21T10:05:10\.000000Z | iis | /api/tickets/ticket\-3714 | [e-3cd9e5855489883a083be612](report.html#e-3cd9e5855489883a083be612) |
| 2026\-08\-21T10:05:23\.000000Z | sysmon | C:\\Windows\\System32\\inetsrv\\w3wp\.exe | [e-edfbccc54f67737793b39083](report.html#e-edfbccc54f67737793b39083) |
| 2026\-08\-21T10:05:30\.000000Z | application | report\_request | [e-d80ff433f8159581ada2f1a8](report.html#e-d80ff433f8159581ada2f1a8) |
| 2026\-08\-21T10:05:30\.000000Z | iis | /api/reports | [e-f465f851ec292994aeb82ed0](report.html#e-f465f851ec292994aeb82ed0) |
| 2026\-08\-21T10:05:30\.020000Z | sysmon | C:\\Windows\\System32\\cmd\.exe | [e-a9dda72ad80a573c2d9eb5db](report.html#e-a9dda72ad80a573c2d9eb5db) |
| 2026\-08\-21T10:05:30\.080000Z | application | process\_launch | [e-5a071b4a17a06082bee6d42a](report.html#e-5a071b4a17a06082bee6d42a) |
| 2026\-08\-21T10:05:50\.000000Z | iis | /api/tickets/ticket\-2316 | [e-6f54b7edfb6abb6c11a278e8](report.html#e-6f54b7edfb6abb6c11a278e8) |
| 2026\-08\-21T10:05:50\.000000Z | application | ticket\_access | [e-9bf82b7f6c901b277deeed20](report.html#e-9bf82b7f6c901b277deeed20) |
| 2026\-08\-21T10:06:07\.000000Z | sysmon | C:\\Windows\\System32\\inetsrv\\w3wp\.exe | [e-0050ae31c1536edf2521d3b8](report.html#e-0050ae31c1536edf2521d3b8) |
| 2026\-08\-21T10:06:10\.000000Z | iis | /api/reports | [e-b9fc8023f14876e2204e0e73](report.html#e-b9fc8023f14876e2204e0e73) |
| 2026\-08\-21T10:06:10\.000000Z | application | report\_request | [e-c487aab91defb92d16a9369e](report.html#e-c487aab91defb92d16a9369e) |
| 2026\-08\-21T10:06:10\.020000Z | sysmon | C:\\Windows\\System32\\cmd\.exe | [e-6bd3dc9d03a346ea4f9686c6](report.html#e-6bd3dc9d03a346ea4f9686c6) |
| 2026\-08\-21T10:06:10\.080000Z | application | process\_launch | [e-7d161008b6034f5a503d3c9a](report.html#e-7d161008b6034f5a503d3c9a) |
| 2026\-08\-21T10:06:10\.300000Z | sysmon | C:\\Windows\\System32\\whoami\.exe | [e-834fe0244e021a3ddf4e414a](report.html#e-834fe0244e021a3ddf4e414a) |
| 2026\-08\-21T10:06:10\.400000Z | sysmon | C:\\Windows\\System32\\cmd\.exe | [e-34f6707f04d6e8b98397694f](report.html#e-34f6707f04d6e8b98397694f) |
| 2026\-08\-21T10:06:10\.500000Z | sysmon | C:\\Windows\\System32\\cmd\.exe | [e-77641da7be8f52fff0b3b730](report.html#e-77641da7be8f52fff0b3b730) |

## Attribution and uncertainty

- \{09199679\-15cd\-a432\-e22e\-0200962fdeb8\}: high; Unique host, child/parent PIDs and bounded launch match; observed parent ProcessGuid and start agree. [e-3957f8d0de39a5358bda165c](report.html#e-3957f8d0de39a5358bda165c), [e-58d588efa579923ed36c1108](report.html#e-58d588efa579923ed36c1108), [e-7f85ba75f653c7bc7e309c12](report.html#e-7f85ba75f653c7bc7e309c12)
- \{0c453832\-04db\-a6a9\-5cd9\-1a0833483697\}: high; Unique host, child/parent PIDs and bounded launch match; observed parent ProcessGuid and start agree. [e-63d0fa5936c98eb5ab5f7dac](report.html#e-63d0fa5936c98eb5ab5f7dac), [e-74b72b2d34528b1833daf021](report.html#e-74b72b2d34528b1833daf021), [e-eacae92f57e42be7251de81e](report.html#e-eacae92f57e42be7251de81e)
- \{26a4fd3e\-8c08\-7e12\-d20f\-f7f04c7c69cb\}: unattributed; No unique instrumented request link; process remains independently observable. [e-3957f8d0de39a5358bda165c](report.html#e-3957f8d0de39a5358bda165c)
- \{632e3462\-77df\-c725\-530e\-bf66458603e1\}: unattributed; No unique instrumented request link; process remains independently observable. [e-74b72b2d34528b1833daf021](report.html#e-74b72b2d34528b1833daf021)
- \{335d029b\-c09c\-eb4d\-b937\-938f4ffa0e95\}: high; Unique host, child/parent PIDs and bounded launch match; observed parent ProcessGuid and start agree. [e-6cd4fcb0c6387f3b467b1761](report.html#e-6cd4fcb0c6387f3b467b1761), [e-8a333ccd5d8c6647046ccac8](report.html#e-8a333ccd5d8c6647046ccac8), [e-eec27cb386cec4c90aebd6bc](report.html#e-eec27cb386cec4c90aebd6bc)
- \{4d6b6814\-5e06\-10f4\-758e\-c48e20763a0c\}: unattributed; No unique instrumented request link; process remains independently observable. [e-eec27cb386cec4c90aebd6bc](report.html#e-eec27cb386cec4c90aebd6bc)
- \{8f5751cb\-78e0\-520f\-9566\-cbf3154e2f4b\}: high; Unique host, child/parent PIDs and bounded launch match; observed parent ProcessGuid and start agree. [e-9f2d769923dfa34d325facb4](report.html#e-9f2d769923dfa34d325facb4), [e-eec27cb386cec4c90aebd6bc](report.html#e-eec27cb386cec4c90aebd6bc), [e-ff73efda0acec908a41a17b7](report.html#e-ff73efda0acec908a41a17b7)
- \{947b812e\-b152\-47c1\-11d8\-53ebe3a6c1d3\}: unattributed; No unique instrumented request link; process remains independently observable. [e-44c6350abc3a5c895571f05d](report.html#e-44c6350abc3a5c895571f05d)
- \{a04779b9\-b299\-f219\-a53f\-28dbb0a0bf09\}: high; Observed ParentProcessGuid chain; Unique host, child/parent PIDs and bounded launch match; observed parent ProcessGuid and start agree. [e-44c6350abc3a5c895571f05d](report.html#e-44c6350abc3a5c895571f05d), [e-7cc941d7f2a9908b0ebabd3f](report.html#e-7cc941d7f2a9908b0ebabd3f), [e-9e25cbbc5c09f242ea2fce79](report.html#e-9e25cbbc5c09f242ea2fce79), [e-db60ba62c67ba3bc399bbafb](report.html#e-db60ba62c67ba3bc399bbafb)
- \{f2477408\-ba9e\-aea5\-27fb\-643d648eecb6\}: high; Unique host, child/parent PIDs and bounded launch match; observed parent ProcessGuid and start agree. [e-0f648897a75aefa4f1b25f32](report.html#e-0f648897a75aefa4f1b25f32), [e-44c6350abc3a5c895571f05d](report.html#e-44c6350abc3a5c895571f05d), [e-686c868170dd18e201c7e252](report.html#e-686c868170dd18e201c7e252), [e-9e25cbbc5c09f242ea2fce79](report.html#e-9e25cbbc5c09f242ea2fce79), [e-db60ba62c67ba3bc399bbafb](report.html#e-db60ba62c67ba3bc399bbafb)
- \{7540f420\-b27e\-620c\-ce45\-58e9f4f65222\}: high; Unique host, child/parent PIDs and bounded launch match; observed parent ProcessGuid and start agree. [e-0050ae31c1536edf2521d3b8](report.html#e-0050ae31c1536edf2521d3b8), [e-34f6707f04d6e8b98397694f](report.html#e-34f6707f04d6e8b98397694f), [e-6bd3dc9d03a346ea4f9686c6](report.html#e-6bd3dc9d03a346ea4f9686c6), [e-77641da7be8f52fff0b3b730](report.html#e-77641da7be8f52fff0b3b730), [e-7d161008b6034f5a503d3c9a](report.html#e-7d161008b6034f5a503d3c9a)
- \{8829f297\-ed1a\-6565\-d7d6\-4ae391ec10e7\}: high; Observed ParentProcessGuid chain; Unique host, child/parent PIDs and bounded launch match; observed parent ProcessGuid and start agree. [e-0050ae31c1536edf2521d3b8](report.html#e-0050ae31c1536edf2521d3b8), [e-6bd3dc9d03a346ea4f9686c6](report.html#e-6bd3dc9d03a346ea4f9686c6), [e-7d161008b6034f5a503d3c9a](report.html#e-7d161008b6034f5a503d3c9a), [e-834fe0244e021a3ddf4e414a](report.html#e-834fe0244e021a3ddf4e414a)
- \{dc23aac9\-1532\-0030\-c4cb\-e918b4210474\}: unattributed; No unique instrumented request link; process remains independently observable. [e-0050ae31c1536edf2521d3b8](report.html#e-0050ae31c1536edf2521d3b8)
- \{56303d90\-2acb\-a141\-ce8d\-1861d70278b1\}: unattributed; No unique instrumented request link; process remains independently observable. [e-cc3b87cc43839ebd40c433db](report.html#e-cc3b87cc43839ebd40c433db)
- \{9197b6dc\-bc50\-cae2\-1000\-2fe0c4a62fc3\}: high; Unique host, child/parent PIDs and bounded launch match; observed parent ProcessGuid and start agree. [e-14793a1aa7fcdf7e45f0686c](report.html#e-14793a1aa7fcdf7e45f0686c), [e-5f301bf3435f8cc37f8cee2c](report.html#e-5f301bf3435f8cc37f8cee2c), [e-cc3b87cc43839ebd40c433db](report.html#e-cc3b87cc43839ebd40c433db)
- \{3e0455f5\-669a\-2e0d\-e00f\-fbbd861af995\}: high; Unique host, child/parent PIDs and bounded launch match; observed parent ProcessGuid and start agree. [e-5a071b4a17a06082bee6d42a](report.html#e-5a071b4a17a06082bee6d42a), [e-a9dda72ad80a573c2d9eb5db](report.html#e-a9dda72ad80a573c2d9eb5db), [e-edfbccc54f67737793b39083](report.html#e-edfbccc54f67737793b39083)
- \{59802d7d\-e425\-a7f2\-c761\-62580654fefa\}: unattributed; No unique instrumented request link; process remains independently observable. [e-edfbccc54f67737793b39083](report.html#e-edfbccc54f67737793b39083)
- \{70f118b6\-4f74\-9584\-0b23\-8e7ed6205010\}: unattributed; No unique instrumented request link; process remains independently observable. [e-7e9c681ebf813d891b3ccf25](report.html#e-7e9c681ebf813d891b3ccf25)
- \{ac654ad6\-9207\-7b0e\-e4ff\-60845b51aa92\}: unattributed; No unique instrumented request link; process remains independently observable. [e-c74ce06592427b10b577b77f](report.html#e-c74ce06592427b10b577b77f)
- \{2f3ea65a\-76e8\-7551\-e5c0\-427659c29833\}: unattributed; No unique instrumented request link; process remains independently observable. [e-185eb09de78a344c4fff46d6](report.html#e-185eb09de78a344c4fff46d6)
- \{463653af\-76dd\-4205\-2452\-c2c7d2080712\}: high; Unique host, child/parent PIDs and bounded launch match; observed parent ProcessGuid and start agree. [e-185eb09de78a344c4fff46d6](report.html#e-185eb09de78a344c4fff46d6), [e-35e0eee8115d291314aabc22](report.html#e-35e0eee8115d291314aabc22), [e-42b620654875aa4d4505e92b](report.html#e-42b620654875aa4d4505e92b)

## Preservation and response

Preserve originals before cleanup. Confirm policy and legitimate maintenance explanations. Use only the project-scoped, dry-run containment workflow after verifying the affected application pool. A file-create event does not prove a file read; a network event does not prove data transfer.

[Normalized records](events.json) · [Observed alerts](alerts.json) · [Correlation](correlation.json) · [Integrity manifest](bundle-manifest.json)

Hashes protect subsequent integrity, not the original producer's truthfulness. See scenario case reports for verified remediation and retest findings.
