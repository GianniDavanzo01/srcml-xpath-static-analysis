def ExecFile(input):
    with open("test_exec.bin", "wb") as f:
        f.write(input)
    os.chmod("test_exec.bin", 0o755)
    os.system("test_exec.bin")