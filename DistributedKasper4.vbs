Option Explicit

' thea test
Const MKEY = "2C91A6A93229E608"
Const WORKERS = 8
Const PASS_LEN = 4
Const CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!$#@+&* 0123456789"

Dim i
Dim objShell
Dim combinations
Dim charsetArray()
Dim startWord
Dim endWord

StringToArray CHARSET, charsetArray
combinations = Len(CHARSET) ^ PASS_LEN

Set objShell = CreateObject("Wscript.Shell")

startWord = WordAtIndex(charsetArray, 1)

For i = 0 To WORKERS - 1    
    endWord = WordAtIndex(charsetArray, Int(combinations / WORKERS) * (i + 1))
    objShell.Run("cmd.exe /K mp64.exe -1" & """" & CHARSET & """ -s " & startWord & " -l " & endWord & " " & FillChars("?1", PASS_LEN) & " | Kasper4.exe " & MKEY)
    startWord = endWord
Next

' Mod for big integers
Function BMod(x, y)
    BMod = x - Int(x / y) * y
End Function

Function StringToArray(s, array)
    Redim array(Len(s))
    
    For i = 1 To Len(s)
        array(i-1) = Mid(s,i,1)
    Next
End Function

Function WordAtIndex(charsetArray, index)
    Dim i    
    Dim calIndex
    Dim rest
    Dim word

    calIndex = index - 1
    rest = 0

    For i = PASS_LEN - 1 To 0 Step - 1
        rest = BMod(calIndex, Len(CHARSET))
        word = charsetArray(rest) & word
        calIndex = Int(calIndex / Len(CHARSET))
    Next
    
    WordAtIndex = word
End Function

Function FillChars(a, count)
    Dim i
    Dim result
    
    For i = 0 To count - 1
        result = result & a
    Next
    
    FillChars = result
End Function