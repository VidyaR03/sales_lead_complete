from functools import wraps
from django.shortcuts import render,redirect,HttpResponse
from Sales.models import *
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.urls import reverse
import json
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password
from django.utils import timezone
from .models import Users, Remark
from django.shortcuts import render, redirect
from django.contrib import messages
from django.urls import reverse
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from datetime import datetime 
from django.core.exceptions import ValidationError
from itertools import chain
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import pdb
from django.db.models import Q,F
from django.db import transaction
from datetime import date
from django.db.models import Count
from django.db.models.functions import ExtractMonth, ExtractYear
from django.db.models.functions import ExtractMonth
from datetime import datetime, timedelta
from django.db.models import Sum
from collections import Counter, defaultdict
from collections import defaultdict
from datetime import datetime
from dateutil.relativedelta import relativedelta
from django.db.models import Count














# Function for create remark

# @login_required

def create_remark(request):
    if request.method == 'POST':
        # Retrieve form data
        reason = request.POST.get('reason')
        id = request.POST.get('id')

        username = request.session['username']


        # Save the remark
        remark = Remark(user=username, reason=reason, customer_id=id)
        remark.save()

        # Redirect back to the show_details view with the customer id as a query parameter
        return redirect(f'/show_details/?id={id}')

    return render(request, 'customer_detail.html')


def show_details(request):
    id = request.GET.get('id')
    executives = cl_Executive.objects.all()
    branches = cl_Branch.objects.all()
    rm1 = cl_Manager.objects.all()
    
    customer = get_object_or_404(Customer, pk=id)
    remark = Remark.objects.filter(customer_id=id)
    # remark = Remark.objects.filter(customer_id=id).order_by('-updation_date')


    # Retrieve the 'name' from the session if it exists
    name = request.session.get('name')
    m_name = request.session.get('m_name')

    role = 'executive' if name else 'manager' if m_name else 'admin'
    context = {
        'customer': customer,
        'remark': remark,
        'executives': executives,
        'branches': branches,
        'rm1': rm1,
        'name': name, 
        'm_name':m_name,
        'role': role,

    }
    return render(request, 'customer_detail.html', context)




################  Add Customer data ########################################

# @login_required(login_url='login_page')

def check_session_access(view_func):
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        if 'roles' in request.session and 'username' in request.session and 'password' in request.session:
            role = request.session['roles']
            username = request.session['username']
            password = request.session['password']
        else:
            return redirect(logoutUser)

      
        try:
            user = Users.objects.get(username=username)
            if password == user.password:
                return view_func(request, *args, **kwargs)
            else:
                return HttpResponseForbidden("Access denied")
        except Users.DoesNotExist:
            return HttpResponseForbidden("Access denied")
        except Exception as e:
            return HttpResponseForbidden("Access denied")

    return wrapped_view

################## Function for display customer list data

from django.http import HttpResponseForbidden


# @check_session_access
def customer_list(request):
    current_date = date.today()

    executives = cl_Executive.objects.all()
    branches = cl_Branch.objects.all()
    rm1 = cl_Manager.objects.all()
    customers = []

    if request.method == 'POST':
        customers = request.POST.getlist('customers')
        for customer_id in customers:
            customer = Customer.objects.get(pk=customer_id)
            
            # Retrieve associated manager and executive information
            manager = cl_Manager.objects.filter(manager_name=customer.manager_name).first()
            executive = cl_Executive.objects.filter(ex_name=customer.ex_name).first()
            
            customers.append({
                'customer': customer,
                'manager': manager,
                'executive': executive,
            })

            customer.url = reverse('customer_detail', args=[customer.pk])
            customer_obj = Customer.objects.get(pk=customer)
            customer_obj.url = reverse('customer_detail', args=[customer_obj.pk])

            # Update the manager and executive fields of the customer
            if manager:
                customer.manager_name = manager.manager_name
            if executive:
                customer.ex_name = executive.ex_name
            customer.save()

            executives_with_customer = cl_Executive.objects.filter(manager_name=customer.manager_name)
            for exec in executives_with_customer:
                exec.manager_name = customer.manager_name
                exec.save()

        
    # Retrieve all customers and associated data
    all_customers = Customer.objects.order_by('-updation_date')
    count = all_customers.count()
    items_per_page = count
    paginator = Paginator(all_customers, items_per_page)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'customers': customers,
        'executives': executives,
        'branches': branches,
        'rm1': rm1,
        'page_obj': page_obj,
        'customer_info': customers,
        'current_date':current_date
    }

    return render(request, 'dd.html', context)






#######################    Customer Add   #################################################

def add_customer(request):


    if request.method == 'POST':
        e_name = request.POST.get("e_name")
        m_name = request.POST.get("m_name")


        manager_name = request.POST.get('manager_name')
        branch_list = request.POST.get('branch_name')
        ex_name = request.POST.get('ex_name')


        company_name = request.POST.get('company_name')
        type_of_client = request.POST.get('type_of_client')
        if type_of_client:
            type_of_client = type_of_client.replace('_', ' ')
      
        subpoints = request.POST.get('category')
        name = request.POST.get('name')
        contact_detail = request.POST.get('contact_detail')
        mail_id = request.POST.get('mail_id')
        address = request.POST.get('address')


        # nature_of_business = request.POST.get('nature_of_business')
        meeting_date = request.POST.get('meeting_date')
        # status_of_client = request.POST.get('status_of_client')
        next_meeting_date_str = request.POST.get('next_meeting_date')
        if next_meeting_date_str:
                next_meeting_date = datetime.strptime(next_meeting_date_str, '%Y-%m-%d').date()
        else:
            next_meeting_date = None
        # package_sold = request.POST.get('package_sold')
        amount = request.POST.get('amount', '0.00')
        if not amount:
            amount = '0.00'
        add_advance = request.POST.get('add_advance', '0.00')   
        if not add_advance:
            add_advance ='0.00'
        balance_payment = request.POST.get('balance_payment', '0.00')   
        if not balance_payment:
            balance_payment ='0.00'
        activation_date_str = request.POST.get('activation_date')
        renewal_date_str = request.POST.get('renewal_date')
        try:
            
            activation_date = datetime.strptime(activation_date_str, '%Y-%m-%d').date()
        except ValueError:
            activation_date = None  # Handle the case of an invalid date format

        try:
            renewal_date = datetime.strptime(renewal_date_str, '%Y-%m-%d').date()
        except ValueError:
            renewal_date = None  # Handle the case of an invalid date format

       
        customer = Customer(
            manager_name =manager_name,
            branch_list=branch_list,
            ex_name=ex_name,
            company_name=company_name,
            type_of_client=type_of_client,
            subpoints=subpoints,
            name=name,
            contact_detail=contact_detail,
            mail_id=mail_id,
            address=address,
           
            # nature_of_business=nature_of_business,
            meeting_date=meeting_date,
            # status_of_client=status_of_client,
            next_meeting_date=next_meeting_date,
            # package_sold=package_sold,
            amount=amount,
            add_advance=add_advance,
            balance_payment=balance_payment,
            activation_date=activation_date,
            renewal_date=renewal_date
        )
        customer.save()
        name = request.session['name']
        if request.session['roles'] == "Admin":
            return redirect('customer_list' )
        elif request.session['roles'] == "Manager":  
            return redirect('manager_dash')
        else:
            return redirect('executive_dash')
        

    return render(request, 'exe_sale.html')

####################### Update Customer 

def update_customer(request, id):
    customers = Customer.objects.get(id=id)
    executives = cl_Executive.objects.all()
    branches = cl_Branch.objects.all() 
    rm1 = cl_Manager.objects.all()
    
    context = {
        'customers': customers,
        'executives':executives,
        'branches':branches,
        'rm1':rm1,
    }

    if request.method == 'POST':
        manager_name = request.POST.get('manager_name')
        branch_name = request.POST.get('branch_name')
        ex_name = request.POST.get('ex_name')
        company_name = request.POST.get('company_name')
        type_of_client = request.POST.get('type_of_client')
        if type_of_client:
            type_of_client = type_of_client.replace('_', ' ')
        subpoints = request.POST.get('category')
        name = request.POST.get('name')
        contact_detail = request.POST.get('contact_detail')
        mail_id = request.POST.get('mail_id')
        address = request.POST.get('address')
    


        # nature_of_business = request.POST.get('nature_of_business')
        meeting_date = request.POST.get('meeting_date')
        # status_of_client = request.POST.get('status_of_client')
        next_meeting_date_str = request.POST.get('next_meeting_date')
        next_meeting_date = None
        if next_meeting_date_str:
            try:
                next_meeting_date = datetime.strptime(next_meeting_date_str, '%Y-%m-%d').date()
            except ValueError:
                raise ValidationError("Next Meeting Date must be in YYYY-MM-DD format.")

        # package_sold = request.POST.get('package_sold')
        amount = request.POST.get('amount', '0.00')
        if not amount:
            amount = '0.00'
        add_advance = request.POST.get('add_advance', '0.00')   
        if not add_advance:
            add_advance ='0.00'
        balance_payment = request.POST.get('balance_payment', '0.00')   
        if not balance_payment:
            balance_payment ='0.00'    
        activation_date_str = request.POST.get('activation_date')
        renewal_date_str = request.POST.get('renewal_date')
        
        activation_date = None
        if activation_date_str:
            activation_date = datetime.strptime(activation_date_str, '%Y-%m-%d').date()

        renewal_date = None
        if renewal_date_str:
            renewal_date = datetime.strptime(renewal_date_str, '%Y-%m-%d').date()
        customers = Customer(
            id=id,
            manager_name =manager_name,
            branch_list = branch_name,
            ex_name=ex_name,
            company_name=company_name,
            type_of_client=type_of_client,
            subpoints=subpoints,
            name=name,
            contact_detail=contact_detail,
            mail_id=mail_id,
            address=address,
         

            # nature_of_business=nature_of_business,
            meeting_date=meeting_date,
            # status_of_client=status_of_client,
            next_meeting_date=next_meeting_date,
            # package_sold=package_sold,
            amount=amount,
            add_advance=add_advance,
            balance_payment=balance_payment,
            activation_date=activation_date,
            renewal_date=renewal_date
        )
        
        customers.save()
        name = request.session['name']
        if request.session['roles'] == "Admin":
            return redirect('customer_list' )
        elif request.session['roles'] == "Manager":  
            return redirect('manager_dash')
        else:
            return redirect('executive_dash', name=name)
            # Replace 'customer_list' with your actual customer list URL name
    return render(request, 'customer_detail.html',context)


# def Edit(request):
#     customers = Customer.objects.all()
#     context = {
#         'customers': customers,
#     }
#     return render(request, 'base.html', context)



# def Delete(request):
#     if request.method == "POST":
#         list_id = request.POST.getlist('id[]')
       
#         for i in list_id:
#             customers = Customer.objects.filter(id=i).first()
#             customers.delete()
 
#     return redirect('customer_list')



################# customer detail page ################################


def Customer_detail(request, pk):

    if request.session['name']:
        name = request.session['name']
    elif request.session['username']:
        name = request.session['username']
    else:
        name = request.session['m_name']

    customer = get_object_or_404(Customer, pk=pk)
    id = customer.id
    remark = Remark.objects.filter(customer_id=id)
    executives = cl_Executive.objects.all()
    branches = cl_Branch.objects.all() 
    rm1 = cl_Manager.objects.all()
   
    context = {
        'customer': customer,
        'remark': remark,
        'executives':executives,
        'branches':branches,
        'rm1':rm1,
        'name':name,
  
    }
    return render(request, 'customer_detail.html', context)






##################  Home Page #######################################


def home(request):
    
    customer_count = Customer.objects.all()
    
    context={
        'customer_count':len(customer_count),
    
    }
    return render(request,'base.html',context)
    
    
#############  Login Page ########################################################


def loginPage(request):
    
    if request.method == 'POST':

        username = request.POST['username']

        password = request.POST['password']
        request.session['username'] = username
        request.session['password'] = password

        try:

            user = Users.objects.get(username=username)

            if password == user.password:

                if user.roles == 'Admin':
                    request.session['roles'] = "Admin"
                    request.session['name'] = user.name
                    return redirect('dashboard')

                elif user.roles == 'Manager':

                    name = user.name

                    return redirect('mandash')  

                elif user.roles == 'Executive':

                    name = user.name

                    return redirect('exedash')

            else:

                error_message = "Invalid username or password."

        except Users.DoesNotExist:

            try:

                manager = cl_Manager.objects.get(username = username)

                if password == manager.password:

                    name = manager.manager_name
                    request.session['roles'] = "Manager"
                    request.session['name'] = manager.manager_name


                    return redirect('mandash')

                else:

                    error_message = "Invalid username or password."

            except cl_Manager.DoesNotExist:

                try:

                    executive = cl_Executive.objects.get(username=username)

                    if password == executive.password:

                        name = executive.ex_name
                        request.session['name'] = executive.ex_name
                        request.session['roles'] = "Executive"

                        return redirect('exedash')

                    else:

                        error_message = "Invalid username or password."

                except cl_Executive.DoesNotExist:

                    error_message = "Invalid username or password."

                    

        return render(request, 'login.html', {'error_message': error_message})




    return render(request, 'login.html')




def logoutUser(request):
    request.session.flush()
    return redirect("login_page")


###########################    sign up    ###################################

def signup(request):
    if request.method == 'POST':
        email = request.POST['username']
        password = request.POST['password']

        # Extract the username from the email
        username = email.split('@')[0]

        # Check if the email is from the allowed domain
        if not email.endswith('@olatechs.com'):
            error_message = "Only users with Olatech email addresses are allowed to register."
            return render(request, 'signup.html', {'error_message': error_message})

        # Check if the username already exists
        if Users.objects.filter(username=username).exists():
            error_message = "Username already exists."
            return render(request, 'signup.html', {'error_message': error_message})

        # Create a new user
        user = Users(username=email, password=password)
        user.save()
        return redirect('login_page')

    return render(request, 'signup.html')



def check_email_exists(request):
    if request.method == 'POST':
        email = request.POST.get("username")
        
        # Check if the email exists in the database
        try:
            user = Users.objects.get(username=email)
        except Users.DoesNotExist:
            messages.error(request, "Email address does not exist.")
            return redirect('check_email_exists')
        
        return redirect('confirm_password', id=user.id)
    
    return render(request, 'forgot_password.html')



def confirm_password(request,id):
    if request.method == 'POST':
        # Retrieve the user object using the user ID from session
     
        
        try:
            user = Users.objects.get(id=id)
        except Users.DoesNotExist:
            messages.error(request, "Invalid password reset link.")
            return redirect('forgot_password')
        
        # Get the new password and confirm password from the form
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        if new_password == confirm_password:
            # Set the new password for the user
            user.password=new_password
            user.save()
            
            # Clear the reset UID and token from session
           
            
            messages.success(request, "Password reset successful. You can now log in with your new password.")
            return redirect('login_page')
        else:
            messages.error(request, "Passwords do not match.")
    
    return render(request, 'confirm_password.html')



############### Branch ###############################################
@check_session_access
def branch_list(request):
    branch = cl_Branch.objects.all()
    return render(request, 'branch.html', {'branches': branch})


@check_session_access
def add_branch(request):
    if request.method == 'POST':
        branch_name = request.POST.get('branch_name')
        branch = cl_Branch(branch_name=branch_name)
        branch.save()
        return redirect('branch_list')
    branches = cl_Branch.objects.all()  # Fetch all branches
    return render(request, 'branch.html', {'branches': branches})

@check_session_access
def update_branch(request, id):
    
    branches = cl_Branch.objects.get(id=id)

    if request.method == 'POST':
        branch_name = request.POST.get('branch_name')
        
        branches = cl_Branch(
            id=id,
            branch_name=branch_name,
            
        )
        branches.save()
        return redirect('branch_list')
    return render(request, 'branch.html')




##############  RM ###############################
@check_session_access
def manager_list(request):
    rm = cl_Manager.objects.all()
    branches = cl_Branch.objects.all() 
    user = User.objects.all 

    return render(request, 'rm.html', {'rm1': rm, 'branches': branches,'user':user})



@check_session_access
def add_rm(request):
    if request.method == 'POST':
        manager_name = request.POST.get('manager_name')
        branch_list = request.POST.get('branch_list')
        username = request.POST.get('username')
        password = request.POST.get('password')
        roles = "Manager"

        rm = cl_Manager(
            manager_name=manager_name,
            branch_list=branch_list,
            username =  username,
            password =password
            )
        rm.save()
        return redirect('manager_list')
    rm1 = cl_Manager.objects.all()  # Fetch all RM
    return render(request, 'rm.html', {'rm1': rm1})




@check_session_access
def update_rm(request, id):

    rm1 = cl_Manager.objects.get(id=id)

    if request.method == 'POST':
        manager_name = request.POST.get('manager_name')
        branch_list = request.POST.get('branch_list')        
        username = request.POST.get('username')        
        password = request.POST.get('password')        
        rm1 = cl_Manager(
            id=id,
            manager_name=manager_name,
            branch_list=branch_list,
            username=username,
            password=password,
            
        )
        rm1.save()
        return redirect('manager_list')
    return render(request, 'rm.html')




######################   Executive  ############################################################
@check_session_access
def executive_list(request):
    executives = cl_Executive.objects.all()
    branches = cl_Branch.objects.all()  # Fetch all branches
    rm1 = cl_Manager.objects.all()
    user = User.objects.all 



    return render(request, 'executive.html', {'executives': executives,'branches':branches,'rm1':rm1,'user':user})

@check_session_access
def add_executive(request):
    if request.method == 'POST':
        ex_name = request.POST.get('ex_name')
        # manager_list = request.POST.get('manager_list')

        branch_list = cl_Branch.objects.filter(branch_name=request.POST.get('branch_list')).first()
        manager_name = request.POST.get('manager_name')
        username = request.POST.get('username')
        password = request.POST.get('password')
       

        executive = cl_Executive(
            ex_name=ex_name, 
            branch_list=branch_list, 
            manager_name=manager_name,
            username =  username,
            password =password
            )
        executive.save()

        return redirect('executive_list')

    branches = cl_Branch.objects.all()
    rm1 = cl_Manager.objects.all()
    executives = cl_Executive.objects.all()

    return render(request, 'executive.html', {'branches': branches, 'rms': rm1,'executives':executives})


from django.shortcuts import get_object_or_404


def manager_dash( request):
    role = request.session['roles']
    username = request.session['username']
    password = request.session['password']
    all_manager = Customer.objects.order_by('-updation_date')

    try:            
        manager = cl_Manager.objects.get(username = username)
        if password == manager.password:
            name = manager.manager_name
            rm = Customer.objects.filter(manager_name=name)
            branches = cl_Branch.objects.all()
            executives = cl_Executive.objects.filter(manager_name=name)
            cl_manager = cl_Manager.objects.get(manager_name = name)
            return render(request,'manager_sales.html', {'rm1': rm, 'branches': branches,'executives':executives,"cl_manager":cl_manager,'all_manager':all_manager})
        else:
            return redirect(logoutUser)       
    except:
        return HttpResponse("Access Denied")






def executive_dash(request):
    role = request.session['roles']
    username = request.session['username']
    password = request.session['password']
    try:            
        executive = cl_Executive.objects.get(username = username)
        if password == executive.password:
            ex_name = executive.ex_name
            request.session['exe_name'] = ex_name
            executives = cl_Executive.objects.all()
            branches = cl_Branch.objects.all()  # Fetch all branches
            rm1 = cl_Manager.objects.all()
            exe_list = Customer.objects.filter(ex_name = ex_name)
            e_name = ex_name
            cl_ex = cl_Executive.objects.filter(ex_name = e_name)
            return render(request, 'exe_sale.html', {'executives': executives,'branches':branches,'rm1':rm1,'exe_list': exe_list,'name':request.session['exe_name'],'e_name':e_name,"cl_ex":cl_ex,'role':role})
        else:
            return redirect(logoutUser)       
    except:
        return HttpResponse("Access Denied")

def update_executive(request, id):
    executives = cl_Executive.objects.get(id=id)

    if request.method == 'POST':
        
        ex_name = request.POST.get('ex_name')
        branch_list = cl_Branch.objects.filter(branch_name=request.POST.get('branch_list')).first()
        manager_name = request.POST.get('manager_name')
        username = request.POST.get('username')
        password = request.POST.get('password')

       
        executives = cl_Executive(
            id=id,
            ex_name=ex_name,
            branch_list=branch_list,
            manager_name=manager_name,
            username=username,
            password=password


            
        )
        executives.save()
        return redirect('executive_list')
    return render(request, 'executive.html')





######## GET RM BY BRANCH ##############################################


def get_branch_info(request,branch):
    branchi = cl_Manager.objects.get(branch_list = branch)

    
    branchi_info = {
        'manager': branchi.manager_name,
    
        }
    return JsonResponse(branchi_info)


##########y  Get Branch and manager  executive ###################################






def get_all_info(request,branch):
    b_id = cl_Branch.objects.get(branch_name=branch)
    branch_id = b_id.id
    branchi = cl_Executive.objects.filter(branch_list=branch_id).first()  # Use filter() and get the first result
    if branchi:
        exe_info = {
            'manager': branchi.manager_name,
            'executive': branchi.ex_name,
        }
        return JsonResponse(exe_info)
    else:
        return JsonResponse({'error': 'No matching cl_Executive found for the provided id'})
    
    
def get_user_info(request, executive):
    executive_obj = cl_Executive.objects.get(ex_name=executive)
    manager = executive_obj.manager_name
    branch = executive_obj.branch_list.branch_name

    response_data = {
        'manager': manager,
        'branch': branch,
    }

    return JsonResponse(response_data)

    

############# ROLES #####################################

def role_display(request):
    roles = Roles.objects.all()
    return render(request, 'roles.html', {'roles': roles})
   


def add_role(request):
    if request.method == 'POST':
        role_name = request.POST.get('role_name')
        branch = Roles(role_name=role_name)
        branch.save()
        return redirect('role_display')
    roles = Roles.objects.all()  # Fetch all branches
    return render(request, 'roles.html', {'roles': roles})



##########   User Create   ###################################################


def user_list(request):
    roles =Roles.objects.all()

    users = Users.objects.all()
    return render(request, 'users.html', {'users': users,'roles':roles})






def register_user(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        roles = request.POST.get('roles')

        user = Users(name=name, username=username, email=email, password=password, roles=roles)
        user.save()
        return redirect('user_list')

    return render(request, 'users.html')





# def staff(request):
#     executives = cl_Executive.objects.all()
#     managers = cl_Manager.objects.all()
#     branches = cl_Branch.objects.all()

#     if request.method == 'POST':
#         executive_name = request.POST['executive_name']
#         branch_name = request.POST['branch_name']
        
#         try:
#             executive = cl_Executive.objects.get(ex_name=executive_name)
            
#             # Create a new manager record
#             manager = cl_Manager.objects.create(
#                 manager_name=executive.ex_name,
#                 branch_list=branch_name,
#                 username=executive.username,
#                 password=executive.password
#             )
            
#             # Remove the executive from the executive list
#             executive.delete()
            
#             # Handle related changes and messages
            
#             return redirect('staff')  # Redirect to the staff page after promotion
            
#         except cl_Executive.DoesNotExist:
#             message = "Executive not found. Promotion to manager failed."
#             return render(request, 'staff.html', {'executives': executives, 'managers': managers, 'message': message, 'branches': branches})
    
#     return render(request, 'staff.html', {'executives': executives, 'managers': managers, 'branches': branches})






# def staff_list(request):
#     executives = cl_Executive.objects.all()
#     managers = cl_Manager.objects.all()

#     context = {
#         'executives': executives,
#         'managers': managers,
#     }
#     return render(request, 'staff.html', context)




# def promoted_manager_leads(request, manager_name):
#     leads_assigned_to_manager = Customer.objects.filter(manager_name=manager_name)
#     return render(request, 'transfer.html', {'leads': leads_assigned_to_manager})


# def promote_executive_to_manager(request):
#     if request.method == 'POST':
#         executive_name = request.POST['executive_name']
        
#         try:
#             # Get the details of the executive to be promoted
#             executive = cl_Executive.objects.get(ex_name=executive_name)
            
#             # Get the details of the manager to whom the executive will be promoted
#             new_manager_name = request.POST['manager_name']
            
#             # Get the IDs of the existing executives to be mapped to the new manager
#             existing_executive_ids = request.POST.getlist('existing_executives')
#             existing_executives = cl_Executive.objects.filter(id__in=existing_executive_ids)
            
#             # Update the manager and executive fields
#             executive.manager_name = new_manager_name
#             executive.save()
            
#             for existing_executive in existing_executives:
#                 existing_executive.manager_name = new_manager_name
#                 existing_executive.ex_name = ''  # Remove previous executive association
#                 existing_executive.save()

#             message = "Executive promoted and executives mapped successfully!"
#             return render(request, 'staff.html', {'message': message})

#         except cl_Executive.DoesNotExist:
#             message = "Executive not found. Promotion and mapping failed."
#             return render(request, 'staff.html', {'message': message})

#     else:
#         # If the request method is GET, just render the empty form
#         executives = cl_Executive.objects.all()
#         managers = cl_Manager.objects.all()
#         branches = cl_Branch.objects.all()
#         return render(request, 'staff.html', {'executives': executives, 'managers': managers, 'branches': branches})


# # from django.shortcuts import redirect

# def add_executive_to_manager(request):
#     if request.method == 'POST':
#         promoted_manager_name = request.POST['promoted_manager']
#         existing_executive_name = request.POST['existing_executive']
        
#         try:
#             promoted_manager = cl_Manager.objects.get(manager_name=promoted_manager_name)
#             existing_executive = cl_Executive.objects.get(ex_name=existing_executive_name)

#             # Update the existing executive's related_manager field
#             existing_executive.related_manager = promoted_manager_name
#             existing_executive.save()

#             message = f"Executive {existing_executive_name} added to manager {promoted_manager_name} successfully!"
#             return render(request, 'staff.html', {'message': message})

#         except (cl_Manager.DoesNotExist, cl_Executive.DoesNotExist):
#             message = "Manager or Executive not found. Adding executive to manager failed."
#             return render(request, 'staff.html', {'message': message})

#     else:
#         # If the request method is GET, just render the empty form
#         return render(request, 'staff.html')
    



# def map_executives(request):
#     managers = cl_Manager.objects.all()
#     executives = cl_Executive.objects.all()

#     if request.method == 'POST':
   
#         new_manager_id = request.POST.get('manager')
#         selected_executives_ids = request.POST.getlist('executives')
 
#         new_manager = cl_Manager.objects.get(id=new_manager_id)
#         branch = new_manager.branch_list
#         branch_id = cl_Branch.objects.get(branch_name = branch)
#         selected_executives = cl_Executive.objects.filter(id__in=selected_executives_ids)
#         messages.success(request, 'Executives successfully mapped to the manager.')

        
#         with transaction.atomic():  # Use atomic transaction to ensure consistency
#             for executive in selected_executives:
#                 # Update the executive's manager_name field
#                 executive.manager_name = new_manager.manager_name
#                 executive.save()
#                 # data = cl_Executive.objects.filter(id=executive.id)
#                 a = cl_Executive.objects.get(id=executive.id)
#                 # cl_Executive.objects.filter(ex_name=a.ex_name).update(manager_name=new_manager.manager_name,branch_list=new_manager.branch_list)
#                 b =cl_Executive.objects.filter(ex_name=executive.ex_name).update(manager_name=executive.manager_name,branch_list=branch_id)

#                 # res1=Customer.objects.filter(ex_name=executive.manager_name).update(manager_name=executive.manager_name,ex_name=a.ex_name,branch_list=new_manager.branch_list)
#                 # res1=Customer.objects.filter(ex_name=executive.manager_name).update(manager_name=executive.manager_name,ex_name=a.ex_name,branch_list=new_manager.branch_list)
#                 # res2= Customer.objects.filter(ex_name=executive.ex_name).update(manager_name=new_manager.manager_name,branch_list=branch)
#                 res3=Customer.objects.filter(ex_name=executive.ex_name).update(manager_name=executive.manager_name,ex_name=a.ex_name,branch_list=new_manager.branch_list)
               
#         return redirect('customer_list') 

#     context = {
#         'managers': managers,
#         'executives': executives,
#     }

#     return render(request, 'staff.html', context)

# def inherit_executives(request, old_manager_name, new_manager_name):
#     old_manager = cl_Manager.objects.get(manager_name=old_manager_name)
#     new_manager = cl_Manager.objects.get(manager_name=new_manager_name)

#     # Update executives under old manager to point to the new manager
#     executives_to_update = cl_Executive.objects.filter(manager=old_manager)
#     for executive in executives_to_update:
#         executive.manager = new_manager
#         executive.save()

#     return redirect('customer_list')  # Redirect to the sales lead panel after updating


def staff(request):
    executives = cl_Executive.objects.all()
    managers = cl_Manager.objects.all()
    assigned_branches = [manager.branch_list for manager in managers] + [executive.branch_list for executive in executives]
    branches = cl_Branch.objects.exclude(branch_name__in=assigned_branches)

    if request.method == 'POST':
        
        executive_name = request.POST.get('executive_name')
        branch_name = request.POST.get('branch_name')
        
        try:
            executive = cl_Executive.objects.get(ex_name=executive_name)
            
            manager = cl_Manager.objects.create(
                manager_name=executive.ex_name,
                branch_list=branch_name,
                username=executive.username,
                password=executive.password
            )
            
            executive.delete()
            
            
            return redirect('staff')  # Redirect to the staff page after promotion
            
        except cl_Executive.DoesNotExist:
            message = "Executive not found. Promotion to manager failed."
            return render(request, 'staff.html', {'executives': executives, 'managers': managers, 'message': message, 'branches': branches})
    
    return render(request, 'staff.html', {'executives': executives, 'managers': managers, 'branches': branches})






def staff_list(request):
    executives = cl_Executive.objects.all()
    managers = cl_Manager.objects.all()

    context = {
        'executives': executives,
        'managers': managers,
    }
    return render(request, 'staff.html', context)



def promoted_manager_leads(request, manager_name):
    leads_assigned_to_manager = Customer.objects.filter(manager_name=manager_name)
    return render(request, 'transfer.html', {'leads': leads_assigned_to_manager})


def promote_executive_to_manager(request):
    if request.method == 'POST':
        executive_name = request.POST['executive_name']
        
        try:
            # Get the details of the executive to be promoted
            executive = cl_Executive.objects.get(ex_name=executive_name)
            
            # Get the details of the manager to whom the executive will be promoted
            new_manager_name = request.POST.get('manager_name')
            
            # Get the IDs of the existing executives to be mapped to the new manager
            existing_executive_ids = request.POST.getlist('existing_executives')
            existing_executives = cl_Executive.objects.filter(id__in=existing_executive_ids)
            
            # Update the manager and executive fields
            executive.manager_name = new_manager_name
            executive.save()
            
            for existing_executive in existing_executives:
                existing_executive.manager_name = new_manager_name
                existing_executive.ex_name = ''  # Remove previous executive association
                existing_executive.save()

            message = "Executive promoted and executives mapped successfully!"
            return render(request, 'staff.html', {'message': message})

        except cl_Executive.DoesNotExist:
            message = "Executive not found. Promotion and mapping failed."
            return render(request, 'staff.html', {'message': message})

    else:
        # If the request method is GET, just render the empty form
        executives = cl_Executive.objects.all()
        managers = cl_Manager.objects.all()
        branches = cl_Branch.objects.all()
        return render(request, 'staff.html', {'executives': executives, 'managers': managers, 'branches': branches})


def add_executive_to_manager(request):
    if request.method == 'POST':
        promoted_manager_name = request.POST['promoted_manager']
        existing_executive_name = request.POST['existing_executive']
        
        try:
            promoted_manager = cl_Manager.objects.get(manager_name=promoted_manager_name)
            existing_executive = cl_Executive.objects.get(ex_name=existing_executive_name)

            # Update the existing executive's related_manager field
            existing_executive.related_manager = promoted_manager_name
            existing_executive.save()

            message = f"Executive {existing_executive_name} added to manager {promoted_manager_name} successfully!"
            return render(request, 'staff.html', {'message': message})

        except (cl_Manager.DoesNotExist, cl_Executive.DoesNotExist):
            message = "Manager or Executive not found. Adding executive to manager failed."
            return render(request, 'staff.html', {'message': message})

    else:
        # If the request method is GET, just render the empty form
        return render(request, 'staff.html')
    



def map_executives(request):
    managers = cl_Manager.objects.all()
    executives = cl_Executive.objects.all()

    if request.method == 'POST':
   
        new_manager_id = request.POST.get('manager')
        selected_executives_ids = request.POST.getlist('executives')
 
        new_manager = cl_Manager.objects.get(id=new_manager_id)
        branch = new_manager.branch_list
        branch_id = cl_Branch.objects.get(branch_name = branch)
        selected_executives = cl_Executive.objects.filter(id__in=selected_executives_ids)
        messages.success(request, 'Executives successfully mapped to the manager.')

        
        with transaction.atomic():  # Use atomic transaction to ensure consistency
            for executive in selected_executives:
                # Update the executive's manager_name field
                executive.manager_name = new_manager.manager_name
                executive.save()
               
                # data = cl_Executive.objects.filter(id=executive.id)
                a = cl_Executive.objects.get(id=executive.id)
                # cl_Executive.objects.filter(ex_name=a.ex_name).update(manager_name=new_manager.manager_name,branch_list=new_manager.branch_list)
                b =cl_Executive.objects.filter(ex_name=executive.ex_name).update(manager_name=executive.manager_name,branch_list=branch_id)
              

                # res1=Customer.objects.filter(ex_name=executive.manager_name).update(manager_name=executive.manager_name,ex_name=a.ex_name,branch_list=new_manager.branch_list)
                # res1=Customer.objects.filter(ex_name=executive.manager_name).update(manager_name=executive.manager_name,ex_name=a.ex_name,branch_list=new_manager.branch_list)
                # res2= Customer.objects.filter(ex_name=executive.ex_name).update(manager_name=new_manager.manager_name,branch_list=branch)
                res3=Customer.objects.filter(ex_name=executive.ex_name).update(manager_name=executive.manager_name,ex_name=a.ex_name,branch_list=new_manager.branch_list)
        return redirect('customer_list') 

    context = {
        'managers': managers,
        'executives': executives,
    }

    return render(request, 'staff.html', context)





def inherit_executives(request, old_manager_name, new_manager_name):
    old_manager = cl_Manager.objects.get(manager_name=old_manager_name)
    new_manager = cl_Manager.objects.get(manager_name=new_manager_name)

    # Update executives under old manager to point to the new manager
    executives_to_update = cl_Executive.objects.filter(manager=old_manager)
    for executive in executives_to_update:
        executive.manager = new_manager
        executive.save()

    return redirect('customer_list')  # Redirect to the sales lead panel after updating


####################    Dashboard        ############################################################################


def dashboard(request):
    

    # Get the current date and time
    result = defaultdict(lambda: defaultdict(int))

    # Get the current date and time
    now = datetime.now()

    # Calculate the start date (12 months ago from the current date)
    start_date = now - relativedelta(months=12)

    # Define the specific values you want to include as keys
    specific_values = ["Interested", "Converted", "To be called", "Decline"]

    # Initialize the counts for the specific values for each month
    for month_key in result.keys():
        for value in specific_values:
            result[month_key][value] = 0

    # Query the database to get subpoints and client status count by month
    data = Customer.objects.filter(updation_date__gte=start_date).values('updation_date', 'subpoints', 'type_of_client')
    data = data.annotate(month=Count('subpoints'), subpoint_count=Count('subpoints'), client_status_count=Count('type_of_client')).order_by('updation_date')

    # Process the data
    for entry in data:
        month_key = entry['updation_date'].strftime('%Y-%m')
        subpoint_value = entry['subpoints']
        client_status = entry['type_of_client']
        subpoint_count = entry['subpoint_count']
        client_status_count = entry['client_status_count']

        result[month_key][subpoint_value] += subpoint_count
        result[month_key][client_status] += client_status_count

    data = dict(result)
  
    
    # count the today's fix meeting
    current_date = date.today()
    fix_meeting_records = Customer.objects.filter(subpoints="Fix Meeting", updation_date__gte=current_date)
    fix_meeting_count = fix_meeting_records.count()
   

    start_of_month = current_date.replace(day=1)
    end_of_month = current_date.replace(day=1, month=current_date.month + 1) - timedelta(days=1)

    # Query to get the total balance payment for the current month based on updation_date
    total_balance_payment = Customer.objects.filter(
        updation_date__gte=start_of_month,
        updation_date__lte=end_of_month
    ).aggregate(total_balance_payment=Sum('balance_payment'))

    # Query to get the total amount for the current month based on updation_date
    total_amount = Customer.objects.filter(
        updation_date__gte=start_of_month,
        updation_date__lte=end_of_month
    ).aggregate(total_amount=Sum('amount'))

    # Retrieve the values from the query results
    total_balance_payment_month = total_balance_payment['total_balance_payment'] or 0
    total_amount_month = total_amount['total_amount'] or 0
  
    customers = Customer.objects.all()
    current_date = timezone.now().date()
    current_meeting_count = Customer.objects.filter(meeting_date=current_date).count()
   


# month wise record  customer sales lead count
    month_counts = {}

    for customer in customers:
        month = customer.updation_date.month
        year = customer.updation_date.year

        # Construct a valid date string in "YYYY-MM" format
        date_string = f"{year}-{month:02d}"

        # Check if the month exists in the dictionary
        if date_string in month_counts:
            month_counts[date_string] += 1
        else:
            month_counts[date_string] = 1

   


# calculate total amount and balance payment 
    month_balance_payments = {}

    for customer in customers:
        month = customer.updation_date.month
        year = customer.updation_date.year
        date_string = f"{year}-{month:02d}"

        if date_string in month_balance_payments:
            # Convert Decimal to float for serialization
            month_balance_payments[date_string] += float(customer.balance_payment)
        else:
            # Convert Decimal to float for serialization
            month_balance_payments[date_string] = float(customer.balance_payment)

    # Prepare data for Chart.js
    labels = list(month_balance_payments.keys())
    data = list(month_balance_payments.values())

    # Pass data to the template context as JSON strings
    labels_json = json.dumps(labels)
    data_json = json.dumps(data)

    customers = Customer.objects.all()
    total_amount = sum(customer.amount for customer in customers)
    total_balance_payment = sum(customer.balance_payment for customer in customers)


# display count for client status

    combinations = Customer.objects.values('type_of_client', 'subpoints').annotate(count=Count('id'))
    # Prepare data for the graph
    combinations_data_key = []
    combinations_data_data = []
    for combo in combinations:
        type_of_client = combo['type_of_client']
        subpoints = combo['subpoints']

        count = combo['count']
        k = f"{type_of_client} - {subpoints}"
        key = k.split('-')[1]
        combinations_data_key.append(key)
        combinations_data_data.append(count)
      
    data = dict(zip(combinations_data_key, combinations_data_data))
    decline_count = data.get(' Decline')
    converted_count = data.get(' Converted')
    interested_count = data.get(' Interested')
    upgraded_count = data.get(' Upgraded')
    to_be_called_count = data.get(' To be called')
    same_package_count = data.get(' Same Package')
    

# count the total sales lead data
    customer_count_data = (
        Customer.objects
        .annotate(month=ExtractMonth('updation_date'))
        .values('month')
        .annotate(count=Count('id'))
        .order_by('month')
    )

    # Prepare the data as a list of dictionaries with monthly counts
    data = [{'month': entry['month'], 'count': entry['count']} for entry in customer_count_data]

    month_wise_status_counts = defaultdict(lambda: defaultdict(int))
    


    for customer in customers:
        month = customer.updation_date.month
        year = customer.updation_date.year
        date_string = f"{year}-{month:02d}"
        # Check if the status matches specific values and increment the count
        if customer.subpoints == 'Interested':
            month_wise_status_counts[date_string]['Interested'] += 1
        elif customer.subpoints == 'Decline':
            month_wise_status_counts[date_string]['Decline'] += 1
        elif customer.subpoints == 'Upgraded':
            month_wise_status_counts[date_string]['Upgraded'] += 1
        elif customer.subpoints == 'Converted':
            month_wise_status_counts[date_string]['Converted'] += 1

    month_wise_status_counts = dict(month_wise_status_counts)
    print("month_wise_status_counts",month_wise_status_counts)

        

    context = {
        'customer_count_data': data,
        'combinations_data_key': combinations_data_key,  # Include the data in the context
        'combinations_data_data': combinations_data_data,  # Include the data in the context
        'customers': customers,
        'total_amount': total_amount,
        'total_balance_payment': total_balance_payment,
        'month_counts_json': json.dumps(month_counts),
        'labels_json': labels_json,
        'data_json': data_json,
        'decline_count':decline_count,
        'converted_count':converted_count,
        'interested_count':interested_count,
        'upgraded_count':upgraded_count,
        'to_be_called_count':to_be_called_count,
        'same_package_count':same_package_count,
        'current_meeting_count':current_meeting_count,
        'total_balance_payment_month':total_balance_payment_month,
        'total_amount_month':total_amount_month,
        'fix_meeting_count': fix_meeting_count,
        'fix_meeting_records': fix_meeting_records,
        'data': data,
        'month_wise_status_counts': json.dumps(month_wise_status_counts),
        # Add the month_wise_status_counts to the context


    }

    return render(request, 'index.html', context)



######################## Manager dashboard #####################################################

def mandash(request):

    customers = cl_Manager.objects.all()

    username = request.session['username']
    password = request.session['password']
   
    manager = cl_Manager.objects.get(username = username,password=password)
    name = manager.manager_name

########## Calculate total amount ##################################
  
    total_amount = Customer.objects.filter(manager_name=name,).aggregate(total_amount=Sum('amount'))
    
######### Calculate  current month amount ########################################

    current_month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    current_month_end = current_month_start.replace(month=current_month_start.month + 1)
    current_month_total_amount = Customer.objects.filter(
    manager_name=name,
    updation_date__gte=current_month_start,
    updation_date__lt=current_month_end
    ).aggregate(current_month_total_amount=Sum('amount'))

    # Retrieve the current month's total amount
    current_month_total_amount = current_month_total_amount['current_month_total_amount'] or 0

########### Calculaate total balance payment ##################################   
    
    total_balance_payment = Customer.objects.filter(   manager_name=name,
      
    ).aggregate(total_balance_payment=Sum('balance_payment'))

######## Calculate current month balance payment  ##############################################    

    current_month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    current_month_end = current_month_start.replace(month=current_month_start.month + 1)
    current_month_balance_payment = Customer.objects.filter(
    manager_name=name,
    meeting_date__gte=current_month_start,
    meeting_date__lt=current_month_end
    ).aggregate(current_month_balance_payment=Sum('balance_payment'))

    # Retrieve the results
    total_balance_payment_amount = total_balance_payment['total_balance_payment'] or 0
    current_month_balance_payment_amount = current_month_balance_payment['current_month_balance_payment'] or 0

############ Calculate manager leads data ##########################################   

    manager_leads_data = (
        Customer.objects
        .filter(manager_name=name)
        .annotate(month=ExtractMonth('updation_date'))
        .values('month')
        .annotate(count=Count('id'))
        .order_by('month')
    )



    manager_data = [{'month': entry['month'], 'count': entry['count']} for entry in manager_leads_data]
   
######### Initialize a defaultdict for month-wise data  #############
    manager_customers = Customer.objects.filter(manager_name=name)

    month_counts = defaultdict(int)

    for customer in manager_customers:

       month = customer.updation_date.month
       year = customer.updation_date.year

    # Construct a valid date string in "YYYY-MM" format
       date_string = f"{year}-{month:02d}"

    # Increment the count for the corresponding month
       if date_string in month_counts:
            month_counts[date_string] += 1
       else:
            month_counts[date_string] = 1
 
    # Convert the defaultdict to a regular dictionary
    month_counts = dict(month_counts)

    # Convert the dictionary to a JSON string
    manager_data_json = json.dumps(month_counts)

         

   



######### Display client status all #############################################

    combinations = Customer.objects.filter(manager_name=name).values('type_of_client', 'subpoints').annotate(count=Count('id'))

    # Prepare data for the graph
    combinations_data_key = []
    combinations_data_data = []
    for combo in combinations:
        type_of_client = combo['type_of_client']
        subpoints = combo['subpoints']
        count = combo['count']
        k = f"{type_of_client} - {subpoints}"
        key = k.split('-')[1]
        combinations_data_key.append(key)
        combinations_data_data.append(count)

    data = dict(zip(combinations_data_key, combinations_data_data))

    # Now you can access the counts for different client statuses
    decline_count = data.get(' Decline', 0)
    converted_count = data.get(' Converted', 0)
    interested_count = data.get(' Interested', 0)
    upgraded_count = data.get(' Upgraded', 0)
    to_be_called_count = data.get(' To be called', 0)
    same_package_count = data.get(' Same Package', 0)


################# Initialize the defaultdict for month-wise status counts###########
    month_wise_status_counts = defaultdict(lambda: defaultdict(int))

    for customer in manager_customers:
        month = customer.updation_date.month
        year = customer.updation_date.year
        date_string = f"{year}-{month:02d}"
        # Check if the status matches specific values and increment the count
        if customer.subpoints == 'Interested':
            month_wise_status_counts[date_string]['Interested'] += 1
        elif customer.subpoints == 'Decline':
            month_wise_status_counts[date_string]['Decline'] += 1
        elif customer.subpoints == 'Upgraded':
            month_wise_status_counts[date_string]['Upgraded'] += 1
        elif customer.subpoints == 'Converted':
            month_wise_status_counts[date_string]['Converted'] += 1

    # Convert the defaultdict to a regular dictionary
    month_wise_status_counts = dict(month_wise_status_counts)

    print("month_wise_status_counts", month_wise_status_counts)


    

    
    

   



    context = {
        'customers':customers,
        'name':name,
        'total_amount':total_amount,
        'total_balance_payment':total_balance_payment,
        'total_balance_payment_amount':total_balance_payment_amount,
        'current_month_balance_payment_amount':current_month_balance_payment_amount,
        'manager_data': manager_data,
        'manager_data_json': manager_data_json,
        'decline_count':decline_count,
        'converted_count':converted_count,
        'interested_count':interested_count,
        'upgraded_count':upgraded_count,
        'to_be_called_count':to_be_called_count,
        'same_package_count':same_package_count,
        'combinations_data_key': combinations_data_key,  
        'combinations_data_data': combinations_data_data,
        'month_wise_status_counts':json.dumps(month_wise_status_counts),
        'current_month_total_amount':current_month_total_amount


    }
    return render(request,'mandash.html',context)


######## Executive Dashboard #################################################

def exedash(request):

    customers = cl_Executive.objects.all()
    username = request.session['username']
    password = request.session['password']
    executive = cl_Executive.objects.get(username = username,password=password)
    name = executive.ex_name
####### Calculate total amount ####################################
    total_amount = Customer.objects.filter(ex_name=name,).aggregate(total_amount=Sum('amount'))

######### Calculate total balance  #######################################    
    total_balance_payment = Customer.objects.filter( ex_name=name,).aggregate(total_balance_payment=Sum('balance_payment'))


########  Calculate current month total amount ###########################################

     
    current_month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    current_month_end = current_month_start.replace(month=current_month_start.month + 1)
    current_month_total_amount = Customer.objects.filter(
    ex_name=name,
    updation_date__gte=current_month_start,
    updation_date__lt=current_month_end
    ).aggregate(current_month_total_amount=Sum('amount'))

    # Retrieve the current month's total amount
    current_month_total_amount = current_month_total_amount['current_month_total_amount'] or 0

###########  Calculate current month balance payment #############################################

    current_month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    current_month_end = current_month_start.replace(month=current_month_start.month + 1)
    current_month_total_balance = Customer.objects.filter(
    ex_name=name,
    updation_date__gte=current_month_start,
    updation_date__lt=current_month_end
    ).aggregate(current_month_total_balance=Sum('balance_payment'))

    # Retrieve the current month's total amount
    current_month_total_balance = current_month_total_balance['current_month_total_balance'] or 0


########## Total Executive Data #################################



    executive_leads_data = (
        Customer.objects
        .filter(ex_name=name)
        .annotate(month=ExtractMonth('updation_date'))
        .values('month')
        .annotate(count=Count('id'))
        .order_by('month')
    )



    executive_data = [{'month': entry['month'], 'count': entry['count']} for entry in executive_leads_data]

    executive_customers = Customer.objects.filter(ex_name=name)

    month_counts = defaultdict(int)

    for customer in executive_customers:

       month = customer.updation_date.month
       year = customer.updation_date.year

    # Construct a valid date string in "YYYY-MM" format
       date_string = f"{year}-{month:02d}"

    # Increment the count for the corresponding month
       if date_string in month_counts:
            month_counts[date_string] += 1
       else:
            month_counts[date_string] = 1
 
    # Convert the defaultdict to a regular dictionary
    month_counts = dict(month_counts)

    # Convert the dictionary to a JSON string
    executive_data_json = json.dumps(month_counts)



######### Display client status all #############################################

    combinations = Customer.objects.filter(ex_name=name).values('type_of_client', 'subpoints').annotate(count=Count('id'))

    # Prepare data for the graph
    combinations_data_key = []
    combinations_data_data = []
    for combo in combinations:
        type_of_client = combo['type_of_client']
        subpoints = combo['subpoints']
        count = combo['count']
        k = f"{type_of_client} - {subpoints}"
        key = k.split('-')[1]
        combinations_data_key.append(key)
        combinations_data_data.append(count)

    data = dict(zip(combinations_data_key, combinations_data_data))

    # Now you can access the counts for different client statuses
    decline_count = data.get(' Decline', 0)
    converted_count = data.get(' Converted', 0)
    interested_count = data.get(' Interested', 0)
    upgraded_count = data.get(' Upgraded', 0)
    to_be_called_count = data.get(' To be called', 0)
    same_package_count = data.get(' Same Package', 0)



################# Initialize the defaultdict for month-wise status counts###########
    month_wise_status_counts = defaultdict(lambda: defaultdict(int))

    for customer in executive_customers:
        month = customer.updation_date.month
        year = customer.updation_date.year
        date_string = f"{year}-{month:02d}"
        # Check if the status matches specific values and increment the count
        if customer.subpoints == 'Interested':
            month_wise_status_counts[date_string]['Interested'] += 1
        elif customer.subpoints == 'Decline':
            month_wise_status_counts[date_string]['Decline'] += 1
        elif customer.subpoints == 'Upgraded':
            month_wise_status_counts[date_string]['Upgraded'] += 1
        elif customer.subpoints == 'Converted':
            month_wise_status_counts[date_string]['Converted'] += 1

    # Convert the defaultdict to a regular dictionary
    month_wise_status_counts = dict(month_wise_status_counts)

    print("month_wise_status_counts", month_wise_status_counts)






    context = {

        'executive':executive,
        'customers':customers,
        'total_amount':total_amount,
        'total_balance_payment':total_balance_payment,
        'current_month_total_amount':current_month_total_amount,
        'current_month_total_balance':current_month_total_balance,
        'executive_data':executive_data,
        'executive_data_json':executive_data_json,
        'decline_count':decline_count,
        'converted_count':converted_count,
        'interested_count':interested_count,
        'upgraded_count':upgraded_count,
        'to_be_called_count':to_be_called_count,
        'same_package_count':same_package_count,
        'combinations_data_key': combinations_data_key,  
        'combinations_data_data': combinations_data_data,
        'month_wise_status_counts':json.dumps(month_wise_status_counts),


    }

    return render(request,'exedash.html',context)


