import pandas as pd
import openpyxl
import time

col_names = ["cpu","user","nice","system","idle","iowait","irq","softirq","steal","guest","guest_nice","cpu1","user1","nice1","system1","idle1","iowait1","irq1","softirq1","steal1","guest1","guest_nice1","","user","nice","system","idle","iowait","irq","softirq","steal","guest","guest_nice","Total Idle","Total Used","Total Idle (%)","Total Used (%)"]

timestr = time.strftime("%Y%m%d")
output = '('+timestr+') TOY_19MC_DCM_SY_CPU_Calculations.xlsx'
writer = pd.ExcelWriter(output, engine='openpyxl') 

def extract_data(filename):
  with open(filename, "r") as f:
    lines = f.readlines()
  del lines[:4]
  #base values
  cpu = [] 
  user = []
  nice = []
  system = []
  idle = []
  iowait = []
  irq = []
  softirq = []
  steal = []
  guest = []
  guest_nice = []
  cpu1 = []
  user1 = []
  nice1 = []
  system1 = []
  idle1 = []
  iowait1 = []
  irq1 = []
  softirq1 = []
  steal1 = []
  guest1 = []
  guest_nice1 = []
  #calculated values
  user_cal = []
  nice_cal = []
  system_cal = []
  idle_cal = []
  iowait_cal = []
  irq_cal = []
  softirq_cal = []
  steal_cal = []
  guest_cal = []
  guest_nice_cal = []
  Total_Idle_cal = []
  Total_Used_cal = []
  Total_Idle_Percent = []
  Total_Used_Percent = []

  for i in lines:
    substr = i.split(" ")
    cpu.append(substr[0])
    user.append(int(substr[1]))
    nice.append(int(substr[2]))
    system.append(int(substr[3]))
    idle.append(int(substr[4]))
    iowait.append(int(substr[5]))
    irq.append(int(substr[6]))
    softirq.append(int(substr[7]))
    steal.append(int(substr[8]))
    guest.append(int(substr[9]))
    guest_nice.append(int(substr[10]))
    cpu1.append(substr[11])
    user1.append(int(substr[12]))
    nice1.append(int(substr[13]))
    system1.append(int(substr[14]))
    idle1.append(int(substr[15]))
    iowait1.append(int(substr[16]))
    irq1.append(int(substr[17]))
    softirq1.append(int(substr[18]))
    steal1.append(int(substr[19]))
    guest1.append(int(substr[20]))
    guest_nice1 .append(int(substr[21]))


  #perform calculations
  counter = 0
  for i in cpu:
    if counter == 0:
      user_cal.append("")
      nice_cal.append("")
      system_cal.append("")
      idle_cal.append("")
      iowait_cal.append("")
      irq_cal.append("")
      softirq_cal.append("")
      steal_cal.append("")
      guest_cal.append("")
      guest_nice_cal.append("")
      Total_Idle_cal.append("")
      Total_Used_cal.append("")
      Total_Idle_Percent.append("")
      Total_Used_Percent.append("")
    else:
      user_cal.append(user[counter]-user[counter-1])
      nice_cal.append(nice[counter]-nice[counter-1])
      system_cal.append(system[counter]-system[counter-1])
      idle_cal.append(idle[counter]-idle[counter-1])
      iowait_cal.append(iowait[counter]-iowait[counter-1])
      irq_cal.append(irq[counter]-irq[counter-1])
      softirq_cal.append(softirq[counter]-softirq[counter-1])
      steal_cal.append(steal[counter]-steal[counter-1])
      guest_cal.append(guest[counter]-guest[counter-1])
      guest_nice_cal.append(guest_nice[counter]-guest_nice[counter-1])
      Total_Idle_cal.append(idle_cal[counter]+iowait_cal[counter])
      Total_Used_cal.append(user_cal[counter]+nice_cal[counter]+system_cal[counter]+iowait_cal[counter]+irq_cal[counter]+softirq_cal[counter]+steal_cal[counter]+guest_cal[counter]+guest_nice_cal[counter])
      Total_Idle_Percent.append(str(Total_Idle_cal[counter] / (Total_Idle_cal[counter]+Total_Used_cal[counter]) * 100)+'%')
      Total_Used_Percent.append(str(Total_Used_cal[counter] / (Total_Idle_cal[counter]+Total_Used_cal[counter]) * 100) +'%')
    counter += 1

  #dump to excel
  data = cpu,user,nice,system,idle,iowait,irq,softirq,steal,guest,guest_nice,cpu1,user1,nice1,system1,idle1,iowait1,irq1,softirq1,steal1,guest1,guest_nice1,pd.Series(),user_cal,nice_cal,system_cal,idle_cal,iowait_cal,irq_cal,softirq_cal,steal_cal,guest_cal,guest_nice_cal,Total_Idle_cal,Total_Used_cal,Total_Idle_Percent,Total_Used_Percent

  df = pd.DataFrame(data)
  df_t = pd.DataFrame(df).T
  df_t.columns = col_names
  print(df_t)

  df_t.to_excel(writer, sheet_name=filename, startrow=2, startcol=12, index=False)


#main - add to filelist as required
filelist = ["cpu_usage_total.txt","dummy_usage_total.txt"]
for filename in filelist:
  extract_data(filename)
  writer.save()