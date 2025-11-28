# Solution Instruction

## Create for your first overview an Intune Report

Its good to know the impact. 
1. Therefore just export the Devices in Intune in a single CSV (include at best all values)
2. Import the data in Excel and create a Pivot of the following fields to Rows:
2.1 Manufacturer
2.2 Model
2.3 SystemManagementBIOSVersion
3. Move the Model from "Rows" right to the "Values" (drag and drop)

Now you will have a comprehensive report of the impact. 
You know how many devices you have per manufacturer and how many devices have which Bios Version in place.

In general desktop devices are better in terms of latest BIOS updates than Laptops.
Desktop devices can be serviced during nights in the office via Wake on LAN.
Laptops (depending on they way how they get updated) are often way behind.