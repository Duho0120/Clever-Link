import paramiko

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

client.connect(
    "127.0.0.1",
    username="sky_1214",
    key_filename=r"C:\Users\ASUS\.ssh\id_ed25519_wsltest"
)

stdin, stdout, stderr = client.exec_command("whoami")
print("접속 성공! 결과:", stdout.read().decode())

client.close()