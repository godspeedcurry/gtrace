package analysis

// BundledSigmaRules contains standard Sigma rules in YAML format.
// In a real product, these would be loaded from an external folder.
var BundledSigmaRules = []string{
	`
title: Whoami Execution
id: proc_recon_whoami
status: experimental
description: Detects the execution of whoami.exe, often used for reconnaissance.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
level: medium
tags:
    - attack.discovery
    - attack.t1033
`,
	`
title: Suspicious Encoded PowerShell
id: proc_susp_powershell_enc
status: stable
description: Detects usage of -enc / -encodedcommand in PowerShell
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_cli:
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
    condition: selection_img and selection_cli
level: high
tags:
    - attack.execution
    - attack.t1059.001
`,
	`
title: LSASS Access or Dumping
id: proc_susp_lsass_dump
description: Detects suspicious access or dumping of LSASS
logsource:
    category: process_creation
    product: windows
detection:
    selection_dump_tools:
        CommandLine|contains:
            - 'procdump'
            - 'comsvcs.dll'
            - 'rundll32'
    selection_target:
        CommandLine|contains:
            - 'lsass'
            - 'minidump'
    condition: selection_dump_tools and selection_target
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001
`,
	`
title: Scheduled Task Creation
id: proc_persist_schtasks
description: Detects creation of scheduled tasks via command line
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/create'
    condition: selection
level: high
tags:
    - attack.persistence
    - attack.t1053.005
`,
	`
title: Suspicious Registry Modification via Reg.exe
id: proc_mod_reg
description: Detects suspicious registry modification Using reg.exe
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\reg.exe'
        CommandLine|contains:
            - ' add '
            - ' import '
            - ' restore '
    condition: selection
level: medium
tags:
    - attack.defense_evasion
    - attack.t1112
`,
	`
title: Bitsadmin Download
id: proc_tool_bitsadmin
description: Detects usage of bitsadmin to download files
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'bitsadmin'
            - '/transfer'
            - '/download'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1197
`,
}
