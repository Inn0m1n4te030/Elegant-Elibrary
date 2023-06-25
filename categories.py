#Differentiate Category
def category(pattern):
    
    pattern = pattern.lower()
    piggybacked="drop"
    union="union"
    stored_procedure="procedure"
    illegal=["sum","avg","count","floor","min","max","substring"]
    encoding=["0x","char","int"]
    inference=["1=0","x=y"]
    time_based=["sleep","waitfor delay"]
    type = ""

    if piggybacked in pattern:
        type = "Piggy-Backed Query"

    elif union in pattern:
        type = "Union Query"

    elif stored_procedure in pattern:
        type = "Stored Procedure"

    elif illegal[0] in pattern or illegal[1] in pattern or illegal[2] in pattern or illegal[3] in pattern or illegal[4] in pattern or illegal[5] in pattern or illegal[6] in pattern:
        type = "Illegal/Logically incorrect query"
 
    elif encoding[0] in pattern or encoding[1] in pattern or encoding[2] in pattern :
        type = "Alternate Encoding"

    elif inference[0] in pattern or inference[1] in pattern  :
        type = "Inference"

    elif time_based[0] in pattern or time_based[1] in pattern  :
        type = "Time-based Query"
        
    else:
        type = "Tautology"

    return type