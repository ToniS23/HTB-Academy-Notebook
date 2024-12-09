
27-07-2024 16:11 pm

Tags: [[Protocols]] [[Recon]] [[Anon or Guest Access]] [[SMB (445)]] [[NetBIOS (137,138,139)]]

References: https://app.hackthebox.com/starting-point


# Dancing

smbclient -L {ip} to list the shares before disconnecting (no pass)

smbclient {\\\\\\ip\\\\share_name} to access specified share (no pass)
also puts us in the smb shell with the smb server of the shares

get {share_name} to download specified share







# Useful Links:

