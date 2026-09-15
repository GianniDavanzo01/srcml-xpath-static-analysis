def TakeInt():
    while True:
       try:
           num = int(input('Enter a number: '))
           assert num > 0
           break
       except ValueError:
           print('Please enter a valid number.')
       except AssertionError:
           print('Please enter a positive number.')
    return num
