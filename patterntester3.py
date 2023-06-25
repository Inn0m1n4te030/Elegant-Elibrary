def match(pattern, string):
    prevpattern = pattern
    if len(pattern) == len(string) and pattern == string:
            return (len(pattern)/len(string)) * 100
    else:
        pattern = pattern.split(" ")
        string = string.split(" ")
        #matched_count = 0
        lenofmatched = 0
        matched = []
        try:
            for i in range(len(string)):
                for j in range(len(pattern)):
                    #if (string[i] == pattern[j]):
                    if(pattern[j] in string[i] and pattern[j] not in matched):
                        matched.append(pattern[j])
                        #matched_count += 1
                        lenofmatched += len(pattern[j])
                              
            return (lenofmatched/len(prevpattern)) * 100
        except IndexError:
            return (lenofmatched/len(prevpattern)) * 100


def patterntester():
    inputString = input()
    print("Input is : "+ inputString)
    knownpatterns = []
    counter = 0
    percentage = 0
    threshold = 80
    longest_match_pattern = ""
    longest_match_percentage = 0
    

    for line in open('knownpatterns.txt', "r"):
        knownpatterns.append(line.rstrip('\n'))
        
    
    for line in knownpatterns:
        percentage = 0
        if len(line) != 0:
            percentage = match(line, inputString)
            if percentage == 100:
                counter += 1
                if len(longest_match_pattern) < len(line) and len(line) == len(inputString):
                    longest_match_pattern = line
                    longest_match_percentage = percentage

            elif percentage > threshold:
                print(f"Pattern is : {line}")
                print(f"Pattern matched : {percentage:.2f} %")
                print("SQL Injection detected!")
                counter += 1

   #modified start
    if len(longest_match_pattern) > 0:
        print("100 % matched pattern is .... " + longest_match_pattern)
        print(f"Pattern is : {longest_match_pattern}")
        print(f"Pattern matched : {longest_match_percentage:.2f} %")
        print("SQL Injection detected by 100 %")
    #modified end

    if counter > 1:
        print("Alerting to admin")
        
patterntester()
