#     month_wise_status_counts = defaultdict(lambda: defaultdict(int))
#     print(month_wise_status_counts,'ssssssssssssssssssssss')

#     for customer in customers:
#         month = customer.updation_date.month
#         year = customer.updation_date.year
#         date_string = f"{year}-{month:02d}"
#         # Check if the status matches specific values and increment the count
#         if customer.subpoints == 'Interested':
#             month_wise_status_counts[date_string]['Interested'] += 1
#         elif customer.subpoints == 'Decline':
#             month_wise_status_counts[date_string]['Decline'] += 1
#         elif customer.subpoints == 'Upgraded':
#             month_wise_status_counts[date_string]['Upgraded'] += 1
#         elif customer.subpoints == 'Converted':
#             month_wise_status_counts[date_string]['Converted'] += 1

#     month_wise_status_counts = dict(month_wise_status_counts)
#     print("month_wise_status_counts",month_wise_status_counts)






# <script>
#     // Parse the JSON data from the Django context
# 	var receiveddata = JSON.parse('{{month_wise_status_counts|escapejs}}')
# 	console.log(receiveddata)

# 	var labels = Object.keys(receiveddata);

	
#         var data = datasets.map(function(dataset) {
#             return {
#                 label: dataset,
#                 data: labels.map(function(label) {
#                     return receiveddata[label][dataset] || 0; // Handle missing data
#                 }),
#             };
#         });

#         // Create the chart
#         var ctx = document.getElementById('barChart').getContext('2d');
#         var barChart = new Chart(ctx, {
#             type: 'bar',
#             data: {
#                 labels: labels,
#                 datasets: data,
#             },
#             options: {
#                 scales: {
#                     x: {
#                         title: {
#                             display: true,
#                             text: 'Months'
#                         }
#                     },
#                     y: {
#                         beginAtZero: true,
#                         title: {
#                             display: true,
#                             text: 'Count'
#                         }
#                     }
#                 }
#             }
#         });
#     </script>
