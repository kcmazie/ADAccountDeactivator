param(
    [Switch]$Console = $False,        #--[ Set to true to enable local console result display. Defaults to false ]--
    [Switch]$Debug = $False           #--[ Set to true to only send results to debug email address. Default to false ]--
    )
<#======================================================================================
          File Name : ADAccountDeactivator.ps1
    Original Author : Kenneth C. Mazie (kcmjr AT kcmjr.com)
                    :
        Description : GUI driven AD account disabler for terminated user accounts.
                    :
          Operation : Requires PowerShell v5. Requires current RSAT tools.
                    : GUI prompts for user to process. Validate button checks account exists and is enabled.
                    : Once validated the Execute button enables. Pressing Execute does the following:
                    : - Disables the account in AD.
                    : - Scrambles the password with 32 random characters.
                    : - Relocates the account to a "Disabled Accounts" OU.
                    : - Edits the description to include todays date and the user who ran the script.
                    : - Adds the account to a "disabled accounts" AD group.
                    : - Sets this group as the new "primary group".
                    : - Removes all AD group memberships except the new disabled accounts group.
                    : - Removes all allowed logon times.
                    : - Emails results
                    :
          Arguments : Normal operation is with no command line options.
                    : -Console $true (Will enable local console output)
                    : -Debug $true (Changes output in GUI to include extra info.)
                    :
           Warnings : Requires a service account with domain admin credentials. Requires current RSAT tools.
                    : Expects a root level OU named "Disabled Accounts".
                    :
              Legal : Public Domain. Modify and redistribute freely. No rights reserved.
                    : SCRIPT PROVIDED "AS IS" WITHOUT WARRANTIES OR GUARANTEES OF
                    : ANY KIND. USE AT YOUR OWN RISK. NO TECHNICAL SUPPORT PROVIDED.
                    : That being said, please let me know if you find bugs!!
                    :
            Credits : Code snippets and/or ideas came from many sources including but
                    : not limited to the following:
                    :
     Last Update by : Kenneth C. Mazie (kcmjr AT kcmjr.com)
                    :
    Version History : v1.00 - 06-26-18 - Original
     Change History : v1.10 - 07-02-18 - Corrected domain detection and display in form.
                    : v1.20 - 08-15-18 - Altered email labels, adjusted email for color. Added missing check for
                    : disabled accounts AD group.
                    :
                    #>
     $Script:ScriptVer = "1.20"
                    <#
=======================================================================================#>
<#PSScriptInfo
.VERSION 1.20
.AUTHOR Kenneth C. Mazie (kcmjr AT kcmjr.com)
.DESCRIPTION
GUI driven AD account deactivator. See script notes for requirements.
#>
#Requires -version 5.0
clear-host

If (!(Get-module ActiveDirectory)){Import-Module ActiveDirectory}
$ErrorActionPreference = "silentlycontinue"

#--[ For Testing ]-------------
#$Script:Console = $true
#$Script:Debug = $true
#------------------------------

$Script:Icon = [System.Drawing.SystemIcons]::Information
$Failure = $False
$Now = Get-Date -F "MM-dd-yyyy_HHmm"
$Script:ReportBody = ""
$Script:ScriptName = ($MyInvocation.MyCommand.Name).split(".")[0] 
$Script:ConfigFile = $PSScriptRoot+'\'+$Script:ScriptName+'.xml'

#--[ Functions ]--------------------------------------------------------------
Function UpdateOutput {
    $Script:OutputBox.update()
    $Script:OutputBox.Select($OutputBox.Text.Length, 0)
    $Script:OutputBox.ScrollToCaret()
}

Function IsThereText ($TargetBox){
  if (($TargetBox.Text.Length -ne 0)){ # -or ($Script:FileNameTextBox.Text.Length -ne 0)){
    Return $true
  }else{
    Return $false
  }
}

Function SendEmail {
    $email = $null
    If ($Script:Debug){$ErrorActionPreference = "stop"}   
    If ($Script:Debug){
        $eMailRecipient = $Script:DebugEmail                                         #--[ Debug destination email address
    }Else{    
        $eMailRecipient = $Script:EmailTo                                            #--[ Destination email address
    }
    $email = New-Object System.Net.Mail.MailMessage
    $email.From = $Script:EmailFrom
    $email.IsBodyHtml = $Script:EmailHTML
    $email.To.Add($eMailRecipient) 
    $email.Subject = $Script:EmailSubject
    $email.Body = $Script:MessageBody 
    $smtp = new-object Net.Mail.SmtpClient($Script:SmtpServer)
    $smtp.Send($email)
    If ($Script:Console){Write-Host "`n--[ Email sent ]--" -ForegroundColor Green}
    $Script:OutputBox.Text += "`n`nEmail sent..."
    UpdateOutput  
}
#--[ End of Functions ]---------------------------------------------------------

#--[ Read and load configuration file ]-----------------------------------------
    If (!(Test-Path $Script:ConfigFile)){       #--[ Error out if configuration file doesn't exist ]--
        $Script:MessageBody = "------------------------------------------------------------------`n" 
        $Script:MessageBody += "--[ AD Account Disabler MISSING CONFIG FILE. Script aborted. ]--`n" 
        $Script:MessageBody += "-------------------------------------------------------------------" 
        SendEmail
        Write-Host $MessageBody -ForegroundColor Red
        break
    }Else{
        [xml]$Script:Configuration = Get-Content $Script:ConfigFile       
        $Script:ScriptName = $Script:Configuration.Settings.General.ScriptName
        $Script:DebugTarget = $Script:Configuration.Settings.General.DebugTarget 
        $Script:DisabledUsersOU = $Script:Configuration.Settings.General.DisabledUsersOU
        $Script:EmailSubject = $Script:Configuration.Settings.Email.Subject
        $Script:EmailTo = $Script:Configuration.Settings.Email.To
        $Script:EmailFrom = $Script:Configuration.Settings.Email.From
        $Script:EmailHTML = $Script:Configuration.Settings.Email.HTML
        $Script:SmtpServer = $Script:Configuration.Settings.Email.SmtpServer
        $Script:DebugEmail = $Script:Configuration.Settings.Email.Debug 
        $Script:UserName = $Script:Configuration.Settings.Credentials.Username
        $Script:EP = $Script:Configuration.Settings.Credentials.Password
        $Script:B64 = $Script:Configuration.Settings.Credentials.Key   
        $Script:BA = [System.Convert]::FromBase64String($B64)
        $Script:SC = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, ($EP | ConvertTo-SecureString -Key $BA)
        $Script:DN = (Get-ADDomain -Credential $Script:SC -Current LoggedOnUser).DNSroot
        #$Script:DN = $Script:Configuration.Settings.Credentials.Domain #--[ Use to pull domain from config file ]--
     
        #--[ Service account configuration with AES key for hardcoded service account ]--
        #--[ See https://www.powershellgallery.com/packages/CredentialsWithKey/1.10/DisplayScript ]--
    }

#--[ Check for required items in Ad ]--
IF(!([adsi]::Exists("LDAP://$Script:DisabledUsersOU"))){
    $Msg = "-- Missing the 'Disabled Accounts' OU in AD --"
    Write-host $Msg -ForegroundColor Red
    $Script:MessageBody = $Msg
    SendEmail
    Break;Break
}

if (![adsi]::Exists("LDAP://$Script:DisabledUsersGroup")) {
    $Msg = "-- Missing the 'Disabled Accounts' group in AD --"
    Write-host $Msg -ForegroundColor Red
    $Script:MessageBody = $Msg
    SendEmail
    Break;Break
}

#--[ Create header for email html content ]--
$Script:MessageBody = @() 
$Script:MessageBody += '
<style Type="text/css">
    table.myTable { border:5px solid black;border-collapse:collapse; }
    table.myTable td { border:2px solid black;padding:5px}
    table.myTable th { border:2px solid black;padding:5px;background: #949494 }
    table.bottomBorder { border-collapse:collapse; }
    table.bottomBorder td, table.bottomBorder th { border-bottom:1px dotted black;padding:5px; }
    tr.noBorder td {border: 0; }
</style>'

$Script:MessageBody += 
'<table class="myTable">
<tr class="noBorder"><td colspan=2><center><h1>- ' + $Script:eMailSubject + ' -</h1></td></tr>
<tr class="noBorder"><td colspan=2><center>The following report displays results from AD account deactivation.</center></td></tr>
<tr class="noBorder"><td colspan=2></tr>
<tr><th>Action</th><th>Result</th></tr>
'  
$Script:HexGray = "#dfdfdf"                                                   #--[ Grey default cell background ]--
$Script:HexOrange = "#ff9900"                                                 #--[ Orange ]--
$Script:HexYellow = "#ffd900"                                                 #--[ Yellow ]--
$Script:HexBlack = "#000000"                                                  #--[ Black ]--
$Script:HexGreen = "#006600"                                                  #--[ Green ]--
$Script:HexRed = "#660000"                                                    #--[ Red ]--

#--------------------------------[ Prep GUI ]-----------------------------------
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 

$Script:Width = (Get-WmiObject -Class Win32_DesktopMonitor | Select-Object ScreenWidth,ScreenHeight).ScreenWidth
$Script:Form = New-Object System.Windows.Forms.Form    
$Script:Form.Size = New-Object System.Drawing.Size(600,400)  
$Script:Notify = new-object system.windows.forms.notifyicon
$Script:Notify.icon = $Script:Icon                                      #--[ NOTE: AvaiLabel tooltip icons are = warning, info, error, and none
$Script:Notify.visible = $true

#--[ Create Form ]--
[int]$Script:FormWidth = 350
[int]$Script:FormHeight = 360
$Script:FormCenter = ($Script:FormWidth / 2)
[int]$Script:ButtonLeft = 55
[int]$Script:ButtonTop = ($Script:FormHeight - 75)
[int]$Script:ButtonHeight = 20
$Script:Form.Text = "$Script:ScriptName v$Script:ScriptVer"
$Script:Form.size = new-object System.Drawing.Size($Script:FormWidth,$Script:FormHeight)
$Script:Form.StartPosition = "CenterScreen"
$Script:Form.KeyPreview = $true
$Script:Form.Add_KeyDown({if ($_.KeyCode -eq "Enter"){$eMailRecipient=$Script:TextBox.Text}})
$Script:Form.Add_KeyDown({if ($_.KeyCode -eq "Escape"){$Script:Form.Close();$Stop = $true}})
$Script:ButtonFont = new-object System.Drawing.Font("New Times Roman",9,[System.Drawing.FontStyle]::Bold)

#-------------------------------------------------------------------------------

#--[ Add Form Title Label ]--
$Script:FormLabelBox = new-object System.Windows.Forms.Label
$Script:FormLabelBox.Font = $Script:ButtonFont
$Script:FormLabelBox.Location = new-object System.Drawing.Size(0,5)
$Script:FormLabelBox.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$Script:FormLabelBox.size = new-object System.Drawing.Size(325,$Script:ButtonHeight)
$Script:FormLabelBox.Text = $Script:ScriptName
$Script:Form.Controls.Add($Script:FormLabelBox)

#--[ Define User and Domain Input Boxes ]---------------------------------------
$bHeight = ($Script:FormCenter-147)    #--[ Top of form text area ]--

#--[ Add User ID Label ]--
$Script:UserIDLabel = New-Object System.Windows.Forms.Label
$Script:UserIDLabel.Location = New-Object System.Drawing.Point(($Script:FormCenter-160),($bHeight))
$Script:UserIDLabel.Size = New-Object System.Drawing.Size(300,$Script:ButtonHeight) 
$Script:UserIDLabel.Text = "Enter the AD User account to process:"
$Script:UserIDLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$Script:Form.Controls.Add($Script:UserIDLabel) 

#--[ Add User ID Text Input Box ]--
$Script:UserIDTextBox = New-Object System.Windows.Forms.TextBox 
$Script:UserIDTextBox.Location = New-Object System.Drawing.Size(($Script:FormCenter-135),($bHeight+22))
$Script:UserIDTextBox.Size = New-Object System.Drawing.Size(110,$Script:ButtonHeight) 
$Script:UserIDTextBox.TabIndex = 4
$Script:ProcessButton.Enabled = $False
$Script:UserIDTextBox.add_TextChanged({
    If (IsThereText $Script:UserIDTextBox){
        $Script:VerifyButton.Enabled = $True
        $Script:ButtonSectionLabel.ForeColor = "Green"
        $Script:VerifyButton.ForeColor = "Green"
        #$Script:VerifyButton.Font = $True #new-object System.Drawing.Font("New Times Roman",9,[System.Drawing.FontStyle]::Bold)
        $Script:ButtonSectionLabel.Location = New-Object System.Drawing.Point(($Script:FormCenter-105),($bHeight-3)) 
        $Script:ButtonSectionLabel.Text = "Click VERIFY to inspect the user."
    }Else{
        $Script:VerifyButton.Enabled = $False
        $Script:VerifyButton.Font.Bold = $False
        $Script:ButtonSectionLabel.ForeColor = "Red"
        $Script:ButtonSectionLabel.Text = "Enter a User ID above."
        $Script:ButtonSectionLabel.Location = New-Object System.Drawing.Point(($Script:FormCenter-80),$bHeight) 
        $Script:ButtonSectionLabel.Size = New-Object System.Drawing.Size(300,$Script:ButtonHeight) 
        $Script:ProcessButton.Enabled = $False
    } 
})
$Script:Form.Controls.Add($Script:UserIDTextBox) 
#--[ Add @ Label ]--
$Script:DNLabel = New-Object System.Windows.Forms.Label
$Script:DNLabel.Location = New-Object System.Drawing.Point(($Script:FormCenter-16),($bHeight+22))
$Script:DNLabel.Size = New-Object System.Drawing.Size(11,$Script:ButtonHeight) 
$Script:DNLabel.Text = "@"
$Script:DNLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$Script:Form.Controls.Add($Script:DNLabel) 
#--[ Add Domain Input Box ]--
$Script:DNTextBox = New-Object System.Windows.Forms.TextBox 
$Script:DNTextBox.Location = New-Object System.Drawing.Size(($Script:FormCenter+3),($bHeight+22))
$Script:DNTextBox.Size = New-Object System.Drawing.Size(110,$Script:ButtonHeight) 
$Script:DNTextBox.Text = $Script:DN
$Script:DNTextBox.TabIndex = 5
$Script:DNTextBox.Enabled = $False
$Script:Form.Controls.Add($Script:DNTextBox) 

#--[ Add Account Status Label ]---------------------------------------------------------------------------
$Script:StatusLabel = New-Object System.Windows.Forms.Label
$Script:StatusLabel.Location = New-Object System.Drawing.Point(($Script:FormCenter-160),($bHeight+50))  
$Script:StatusLabel.Size = New-Object System.Drawing.Size(110,$Script:ButtonHeight) 
$Script:StatusLabel.Text = "Target User Status :"
$Script:Form.Controls.Add($Script:StatusLabel) 
#--[ Add Account Status Text ]--
$Script:TargetStatusText = New-Object System.Windows.Forms.TextBox
$Script:TargetStatusText.Location = New-Object System.Drawing.Point(($Script:FormCenter-50),($bHeight+50))  
$Script:TargetStatusText.Size = New-Object System.Drawing.Size(188,$Script:ButtonHeight) 
$Script:TargetStatusText.Text = ""
$Script:TargetStatusText.Enabled = $False
$Script:Form.Controls.Add($Script:TargetStatusText) 

#--[ Add Target Name Label ]-------------------------------------------------------------------------------
$Script:TargetNameLabel = New-Object System.Windows.Forms.Label
$Script:TargetNameLabel.Location = New-Object System.Drawing.Point(($Script:FormCenter-160),($bHeight+70))  
$Script:TargetNameLabel.Size = New-Object System.Drawing.Size(110,$Script:ButtonHeight) 
$Script:TargetNameLabel.Text = "Target User Name :"
$Script:Form.Controls.Add($Script:TargetNameLabel) 
#--[ Add Target Name Text ]--
$Script:TargetNameText = New-Object System.Windows.Forms.TextBox
$Script:TargetNameText.Location = New-Object System.Drawing.Point(($Script:FormCenter-50),($bHeight+70))  
$Script:TargetNameText.Size = New-Object System.Drawing.Size(188,$Script:ButtonHeight) 
$Script:TargetNameText.Text = ""
$Script:TargetNameText.Enabled = $False
$Script:Form.Controls.Add($Script:TargetNameText) 

#--[ Add Target Department Label ]------------------------------------------------------------------------
$Script:TargetDeptLabel = New-Object System.Windows.Forms.Label
$Script:TargetDeptLabel.Location = New-Object System.Drawing.Point(($Script:FormCenter-160),($bHeight+90))  
$Script:TargetDeptLabel.Size = New-Object System.Drawing.Size(110,$Script:ButtonHeight) 
$Script:TargetDeptLabel.Text = "Target Department :"
$Script:Form.Controls.Add($Script:TargetDeptLabel) 
#--[ Add Target Department Text ]--
$Script:TargetDeptText = New-Object System.Windows.Forms.TextBox
$Script:TargetDeptText.Location = New-Object System.Drawing.Point(($Script:FormCenter-50),($bHeight+90))  
$Script:TargetDeptText.Size = New-Object System.Drawing.Size(188,$Script:ButtonHeight) 
$Script:TargetDeptText.Text = ""
$Script:TargetDeptText.Enabled = $False
$Script:Form.Controls.Add($Script:TargetDeptText) 

#--[ Add Target AD OU Label ]------------------------------------------------------------------------
$Script:TargetOULabel = New-Object System.Windows.Forms.Label
$Script:TargetOULabel.Location = New-Object System.Drawing.Point(($Script:FormCenter-70),($bHeight+115))  
$Script:TargetOULabel.Size = New-Object System.Drawing.Size(125,$Script:ButtonHeight) 
$Script:TargetOULabel.Text = "--- Status Messages ---"
$Script:Form.Controls.Add($Script:TargetOULabel) 

#--[ Define Output Box ]--------------------------------------------------------
$Script:OutputBox = new-object System.Windows.Forms.richtextbox
$Script:OutputBox.location = new-object system.drawing.size(($Script:FormCenter-158),($Script:FormCenter-10)) 
$Script:OutputBox.size = new-object system.drawing.size(300,90)
$Script:OutputBox.TabIndex = 8
$Script:OutputBox.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$Script:OutputBox.MultiLine = $True 
$Script:OutputBox.font = "Consolas"
$Script:OutputBox.ScrollBars = "Vertical" 
$Script:OutputBox.Text = ""
$Script:OutputBox.ForeColor = "Blue"
$Script:form.controls.add($Script:OutputBox)

#--[ Define Stop/Go Buttons ]---------------------------------------------------
$bHeight = ($Script:FormCenter+88)    #--[ Common section height setting ]--
#--[ Add Button Label ]--
$Script:ButtonSectionLabel = New-Object System.Windows.Forms.Label
$Script:ButtonSectionLabel.Text = "Enter a User ID above."
$Script:ButtonSectionLabel.Location = New-Object System.Drawing.Point(($Script:FormCenter-80),($bHeight-3)) 
$Script:ButtonSectionLabel.Size = New-Object System.Drawing.Size(300,$Script:ButtonHeight) 
$Script:ButtonSectionLabel.ForeColor = "Red"
$Script:ButtonSectionLabel.Font = $Script:ButtonFont
$Script:Form.Controls.Add($Script:ButtonSectionLabel) 

#--[ Add VERIFY Button ]--
$Script:VerifyButton = new-object System.Windows.Forms.Button
$Script:VerifyButton.Location = new-object System.Drawing.Size(($Script:FormCenter-150),($bHeight+22))
$Script:VerifyButton.Size = new-object System.Drawing.Size(90,25)
$Script:VerifyButton.TabIndex = 2
$Script:VerifyButton.Text = "Verify"
$Script:VerifyButton.Enabled = $False
$Script:VerifyButton.Font = $Script:ButtonFont
$Script:VerifyButton.Add_Click({
    $Script:Result = "x"
    Try{
        $Script:Result = Get-AdUser -Credential $Script:SC -Identity $Script:UserIDTextBox.Text -Properties * -ErrorAction "stop"
    }Catch{
        If ($Script:Debug){
            $Script:OutputBox.Text += "`n$_.Exception.Message"    #--[ Enable to include the error message in output ]--
            UpdateOutput
        }    
    }    

    If ($Script:Result.enabled ){
        $Script:MessageBody += '<tr><td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>Target Account</td>'
        $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>' + $Script:UserIDTextBox.Text.ToUpper() + ' (' + $Script:Result.DisplayName + ')</td></tr>'
        $Script:MessageBody += '<tr><td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>Initial Account Status</td>'
        $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexRed + '>Enabled</td></tr>'
        $Script:TargetStatusText.Text = "Enabled"    
        $Script:TargetNameText.Text = $Script:Result.DisplayName
        $Script:TargetDeptText.Text = $Script:Result.Department
        $Script:OutputBox.Text = "Target user initial OU:`n"
        $Script:OutputBox.Text += $Script:Result.DistinguishedName 
        $Script:MessageBody += '<tr><td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>Initial Account Location</td>'
        $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>' + $Script:Result.DistinguishedName + '</td></tr>'
        UpdateOutput
        $Script:TargetOUText.Multiline = $true
        $Script:TargetOUText.ScrollBars = "Horizontal"
        $Script:TargetOUText.WordWrap = $true
        $Script:ProcessButton.ForeColor = "Green"
        $Script:ProcessButton.Enabled = $True
        $Script:ButtonSectionLabel.Location = New-Object System.Drawing.Point(($Script:FormCenter-119),($bHeight-3)) 
        $Script:ButtonSectionLabel.Text = "Click EXECUTE to deactivate the user."
        $Script:VerifyButton.Enabled = $False
    }ElseIf ($Script:Result.enabled -eq $false){
        $Script:TargetStatusText.Text = " --- Already Disabled ---"  
        $Script:ProcessButton.Enabled = $False
        $Msg =  "`nUser: "+$Script:UserIDTextBox.Text+" is already disabled..."
        $Script:OutputBox.Text = $Msg
        UpdateOutput
    }Else{
        $Script:TargetStatusText.Text = " --- Invalid user ---"  
        $Script:TargetNameText.Text = ""
        $Script:TargetDeptText.Text = ""
        $Script:ProcessButton.Enabled = $False
        $Script:OutputBox.Text = "`n-- User account not found in AD. Try again..." 
        UpdateOutput
    }
    
})
$Script:Form.Controls.Add($Script:VerifyButton)

#--[ Add CLOSE Button ]--
$Script:CloseButton = new-object System.Windows.Forms.Button
$Script:CloseButton.Location = new-object System.Drawing.Size(($Script:FormCenter-50),($bHeight+22))
$Script:CloseButton.Size = new-object System.Drawing.Size(90,25)
$Script:CloseButton.TabIndex = 1
$Script:CloseButton.Text = "Cancel/Close"
$Script:CloseButton.Add_Click({$Script:Form.close();$Stop = $true})
$Script:Form.Controls.Add($Script:CloseButton)

#--[ Add EXECUTE Button ]--
$Script:ProcessButton = new-object System.Windows.Forms.Button
$Script:ProcessButton.Location = new-object System.Drawing.Size(($Script:FormCenter+50),($bHeight+22))
$Script:ProcessButton.Size = new-object System.Drawing.Size(90,25)
$Script:ProcessButton.Text = "Execute"
$Script:ProcessButton.Enabled = $False
$Script:ProcessButton.Font = $Script:ButtonFont
$Script:ProcessButton.TabIndex = 3
$Script:ProcessButton.Add_Click({
    #--[ Disable account in AD ]--
    $Script:ProcessButton.Enabled = $False
    $Script:OutputBox.Text += "`n`nDisabling target account..."
    $Script:MessageBody += '<tr><td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>Disabling account</td>'
    UpdateOutput
    Get-ADUser -Identity $Script:UserIDTextBox.Text -Credential $Script:SC | Disable-ADAccount  #-Whatif
    Start-Sleep -Milliseconds 500
    $Script:ResultUpdate = Get-AdUser -Credential $Script:SC -Identity $Script:UserIDTextBox.Text -Properties * 
    If (!($Script:ResultUpdate.Enabled)){
        $Script:TargetStatusText.Text = "Disabled"
        $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexGreen + '>Successfully disabled account.</td></tr>'
        $Script:OutputBox.Text += "`n-- Successful..."        
        UpdateOutput
    }Else{
        $Failure = $True
        $Script:TargetStatusText.Text = " -ERROR-"
        $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexRed + '>An Error occurred disabling the target.</td></tr>'
        $Script:OutputBox.Text += "`nAn Error occurred disabling the target..."
        UpdateOutput    
    }

    If (!$Failure){
        #--[ Scramble Password ]--
        $Script:OutputBox.Text += "`n`nScrambling target password..."
        $Script:MessageBody += '<tr><td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>Scrambling password</td>'
        UpdateOutput
        $TargetPassword = ""
        $Length = 32
        #--[ Optional Codesets ]--
        #$CodeSet = "☺☻♥♦♣♠•◘○◙♂♀♪♫☼►◄↕‼¶§▬↨↑↓→←∟↔▲▼!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~⌂ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙⋅√ⁿ²■"
        $CodeSet = "!#%&'()+,-.0123456789;<=>@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}"    #-- [ invalid characters: /\: ]--
        #$CodeSet = "abcdefghijklmnopqstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ!_<>~$%@#"
        $Character = for ($i = 0; $i -lt $CodeSet.length; $i++) { $CodeSet[$i] }
        for ($i = 1; $i -le $Length; $i++){
            $TargetPassword += $(get-random $Character)
            if ($i -eq $Length) {
                #--[ Optional Outputs ]--
                #$Password | clip ; #--[ Output to clipboard ]--
                #write-host "$Length Char Password: $Password" #--[ Output to Screen ]--
                #[System.Windows.Forms.Messagebox]::Show($Password,"$Length Char Password:") #--[ Output to a messagebox ]--
                Try{
                    Set-ADAccountPassword -Identity $Script:UserIDTextBox.Text -Credential $Script:SC -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $TargetPassword -Force)
                    $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexGreen + '>Successfully scrambled password.</td></tr>'
                    $Script:OutputBox.Text += "`n-- Successful..."        
                }Catch{
                    $Script:OutputBox.Text += "`nAn Error occurred scrambling the password."
                    $Script:OutputBox.Text += "`n-- $_.Exception.Message"
                    $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexRed + '>' + $_.Exception.Message + '</td></tr>'
                }  
                UpdateOutput 
            }
        }   

        #--[ Relocate to disabled accounts OU ]--
        $Script:MessageBody += '<tr><td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>Relocating OU</td>'
        $Script:OutputBox.Text += "`n`nRelocating target account..."
        UpdateOutput
        Get-ADUser -Credential $Script:SC -Identity $Script:UserIDTextBox.Text | Move-ADObject -TargetPath (Get-ADOrganizationalUnit -Filter 'Name -eq "Disabled Accounts"')  #-WhatIf
        Start-Sleep -Milliseconds 500
        $Script:ResultUpdate = Get-AdUser -Credential $Script:SC -Identity $Script:UserIDTextBox.Text -Properties * 
        If (!($Script:Result.DistinguishedName -eq $Script:ResultUpdate.DistinguishedName)){
            $Script:OutputBox.Text += "`n-- Successful..."
            $Script:OutputBox.Text += "`n`nTarget user new OU:`n"
            $Script:OutputBox.Text += $Script:ResultUpdate.DistinguishedName #.split(',')#[1]
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexGreen + '>Successfully relocated account to "Disabled Accounts" OU.</td></tr>'
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>New AD OU</td>'
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>' + $Script:ResultUpdate.DistinguishedName + '</td></tr>'
            UpdateOutput
        }Else{
            $Script:OutputBox.Text += "`nAn Error occurred relocating the target."
            $Script:OutputBox.Text += "`n-- $_.Exception.Message"
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexRed + '>' + $_.Exception.Message + '</td></tr>'
        }
        UpdateOutput    

        #--[ Adjust account description ]--
        $Script:OutputBox.Text += "`n`nAdjusting target description..."
        $Script:MessageBody += '<tr><td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>Updating Description</td>'
        Try {
            Get-Aduser -Credential $Script:SC -Identity $Script:UserIDTextBox.Text -Properties Description | ForEach-Object { Set-ADUser $_ -Description "(DISABLED $Now by $Env:Username) $($_.Description)" }
            $Script:OutputBox.Text += "`n-- Successful..."
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexGreen + '>Successfully updated account description with todays date.</td></tr>'
        }Catch{
            $Script:OutputBox.Text += "`nAn Error occurred adjusting the target description."
            $Script:OutputBox.Text += "`n-- $_.Exception.Message"
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexRed + '>' + $_.Exception.Message + '</td></tr>'
        }
        UpdateOutput

        #--[ Add user to Disabled Accounts group ]--
        $Script:OutputBox.Text += "`n`nJoining ""Disabled Accounts"" group..."
        $Script:MessageBody += '<tr><td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>Joining "Disabled Accounts"</td>'
        Try{
            Add-ADGroupMember -Credential $Script:SC -Identity 'Disabled Accounts' -Members (get-aduser -Identity $Script:UserIDTextBox.Text)
            $Script:OutputBox.Text += "`n-- Successful..."
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexGreen + '>Successfully joined to "Disabled Accounts" AD group...</td></tr>'
        }Catch{
            $Script:OutputBox.Text += "`nAn Error occurred joining disabled accounts group."
            $Script:OutputBox.Text += "`n-- $_.Exception.Message"
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexRed + '>' + $_.Exception.Message + '</td></tr>'
        }
        UpdateOutput

        #--[ Reset users primary group to Disabled Accounts ]--
        $Script:OutputBox.Text += "`n`n""Disabled Accounts"" set as primary group..."
        $Script:MessageBody += '<tr><td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>Updating Primary AD Group</td>'
        Try{
            $GroupToken = get-adgroup -Identity "Disabled Accounts" -Credential $Script:SC -properties @("primaryGroupToken")
            Get-ADUser -Credential $Script:SC -Identity $Script:UserIDTextBox.Text | Set-Aduser -replace @{primaryGroupID=$GroupToken.primaryGroupToken}
            $Script:OutputBox.Text += "`n-- Successful..."
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexGreen + '>Successfully set Primary Group to "Disabled Accounts"...</td></td>'
        }Catch{
            $Script:OutputBox.Text += "`nAn Error occurred resetting the primary group."
            $Script:OutputBox.Text += "`n-- $_.Exception.Message"
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexRed + '>' + $_.Exception.Message + '</td></tr>'
        }
        UpdateOutput

        Start-Sleep -Milliseconds 1000
        #--[ Remove user from all groups except Disabled Accounts ]--
        $Script:OutputBox.Text += "`n`nRemoving target from all AD groups..."
        $Script:MessageBody += '<tr><td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>Removing AD Groups</td>'
        Try{
            $ADgroups = Get-ADPrincipalGroupMembership -Identity $Script:UserIDTextBox.Text -Credential $Script:SC | Where-Object {$_.Name -NotLike "*Disabled*"}
            if ($ADgroups -ne $null){
                Remove-ADPrincipalGroupMembership -Identity $Script:UserIDTextBox.Text -Credential $Script:SC -MemberOf $ADgroups -Confirm:$false # -WhatIf
            }
            $Script:OutputBox.Text += "`n-- Successful..."
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexGreen + '>Successfully removed all remaining AD group memberships from target account.</td></tr>'
        }Catch{
            $Script:OutputBox.Text += "`nAn Error occurred purging all groups."
            $Script:OutputBox.Text += "`n-- $_.Exception.Message"
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexRed + '>' + $_.Exception.Message + '</td></tr>'
        }
        UpdateOutput

        #--[ Remove all allowed logon times ]--
        $Script:OutputBox.Text += "`n`nDenying target all logon times..."
        $Script:MessageBody += '<tr><td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>Clearing Logon Hours</td>'
        $LogonHoursBinary = 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        Try{
            Get-ADUser -Credential $Script:SC -Identity $Script:UserIDTextBox.Text | Set-ADUser -Replace @{Logonhours = [Byte[]]$LogonHoursBinary} 
            $Script:OutputBox.Text += "`n-- Successful..."
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexGreen + '>Successfully denied all logon times for target account. </td></tr>'
        }Catch{
            $Script:OutputBox.Text += "`nAn Error occurred removing logon hours."
            $Script:OutputBox.Text += "`n-- $_.Exception.Message"
            $Script:MessageBody += '<td bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexRed + '>' + $_.Exception.Message + '</td></tr>'
        }
        UpdateOutput

        #--[ Completed ]--
        $Script:MessageBody += '<tr><td colspan=2 bgcolor=' + $Script:HexGray + '><font color=' + $Script:HexBlack + '>Target processing completed...</td></tr></table>'
        $Script:MessageBody += '<br><br>Script Executed On : ' + $Now 
        $Script:MessageBody += '<br>Script Executed By : ' + $Env:Username 
        $Script:MessageBody += '<br>Script Version : ' + $Script:ScriptVer 
        SendEmail
        $Script:OutputBox.Text += "`n`n--- Completed ---`n"
        If ($Script:Console){Write-Host "--- Completed ---" -ForegroundColor Red}
        UpdateOutput
    }
})
$Script:Form.Controls.Add($Script:ProcessButton)

#--[ Open Form ]--
$Script:Form.topmost = $true
$Script:Form.Add_Shown({$Script:Form.Activate()})
[void] $Script:Form.ShowDialog()

if($Script:Stop -eq $true){$Script:Form.Close();break;break}

<#--[ Sample XML config file ]---------------------------------------------------------------
<!-- Settings & Configuration File -->
<Settings>
    <General>
        <ScriptName>AD User Account Deactivation Report.</ScriptName>
        <DebugTarget>testpc</DebugTarget>
        <DisabledUsersOU>OU=disabled accounts,DC=domain,DC=com</DisabledUsersOU>
        <DisabledUsersGroup>CN=Disabled Accounts,OU=disabled accounts,DC=domain,DC=com</DisabledUsersGroup>
    </General>
    <Email>
        <From>AD_Account_Deactivation@mydomain.com</From>
        <To>distribution@mydomain.com</To>
        <Debug>me@mydomain.com</Debug>
        <Subject>AD User Account Deactivation Report.</Subject>
        <HTML>$true</HTML>
        <SmtpServer>10.100.10.10</SmtpServer>
    </Email>
    <Credentials>
        <Domain>mydomain.com</Domain>
        <UserName>domain\serviceaccount</UserName>
        <Password>7649AeQA0DQANgA0AGEAMAAwADQAZgBiAGNgBiADAANwBkADEANAA4AGQAZgA3ADIAYQADQANgA0AGEAMAAwADQAZgBiAGNgBiADAANwBkADEANAA4AGQAZgA3ADIAYQAwADYAZAQAZgA3ADIAYQAwDQANgA0AGEAMAAwADQAZgBiAGNgBiADAANwBkADEANAA4AGQAZgA3ADIAYQAwADYAZAkAGYAZAA=</Password>
        <Key>kdhCh7HCvEAYQBhAGQANQBkADQAZQAzAGYANAAyADUAYXN0IObie8mE=</Key>
    </Credentials>
</Settings>
#>