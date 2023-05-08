# ADAccountDeactivator
GUI driven AD account disabler for terminated user accounts.

Originally uploaded to the PowertShell Gallery in 2018.

- Requires PowerShell v5. Requires current RSAT tools.
- GUI prompts for user to process. Validate button checks account exists and is enabled.
- Once validated the Execute button enables. Pressing Execute does the following:
- Disables the account in AD.
- Scrambles the password with 32 random characters.
- Relocates the account to a "Disabled Accounts" OU.
- Edits the description to include todays date and the user who ran the script.
- Adds the account to a "disabled accounts" AD group.
- Sets this group as the new "primary group".
- Removes all AD group memberships except the new disabled accounts group.
- Removes all allowed logon times.
- Emails results
