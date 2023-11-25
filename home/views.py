from django.shortcuts import render
import requests
from home.rules import Rules  # Make sure that 'rules' module is available

def home(request):
    if request.method == 'GET':
        # Additional logic for handling GET requests
        return render(request, 'home/index.html')
    
    elif request.method == 'POST':
        # Additional logic for handling POST requests
        domain = request.POST.get('domain')  # Use request.POST.get to avoid KeyError

        try:
            rules = Rules(domain)
            res_rules, score = rules.run_rules()

            context = {
                "data": res_rules,
                "score": score,
                "domain": domain
            }

            return render(request, 'home/index.html', context)
        
        except requests.exceptions.RequestException as e:
            # Render an error template with the exception message
            context = {"error_message": str(e)}
            return render(request, 'error_template.html', context)
