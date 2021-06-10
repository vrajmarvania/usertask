from django.shortcuts import render


def sing_in(request):
    return render(request,'sing_in.html')
def sing_up(request):
    return render(request,'sing_up.html')