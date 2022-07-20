# Samples of rdata.table searches of WireShark (CSV) packet dissections
# 8:49 PM 7/10/2022 -RMF
# libraries
library(data.table)
library(lubridate)
library(stringi)
library(lattice)
setwd("D:/tools") # your path to packet dumps and CSV exports

# Packet list column format
# Wireshark fields for packet dissector CSV export.
# Each pair of strings consists of a column title and its format
# from "C:\Users\%username%\AppData\Roaming\Wireshark\preferences:"
cat('gui.column.format: 
	"No.", "%m",
	"Date", "%Yt", 
	"Time", "%t",
	"Delta", "%Tt",
	"Length", "%L",
	"Source", "%s",
	"Destination", "%d",
	"Protocol", "%p",
	"SrcPort", "%rS",
	"DstPort", "%rD",
	"Info", "%i",
')


# WireShark: File | Export Packet Dissections | As CSV
# options, variables
options(digits=6)
options("digits.secs"=6)
numOS <- function(x) {as.integer(x/100000)}
roundOS <- function(x) {round(x/100000,5)}

# Creating  YMD(IDat) HMS(ITime) MS(num) fields from Absolute (POSc)Date '%Yt" field
# fread("07.14.2022.csv")
# Add separate fields YMD, HMS, MS
z1 <- fread("07.14.2022.csv",integer64="integer64")[
,c("YMD","HMS"):= tstrsplit(ymd_hms(Date)," ",type.convert=list(as.IDate=1L,as.ITime=2L))]
z1[,MS:= tstrsplit(ymd_hms(Date),".",fixed=TRUE, type.convert=list(as.numeric=2L),keep=2)]
#z1[,OS:= tstrsplit(ymd_hms(Date),".",fixed=TRUE, type.convert=list(roundOS=2L),keep=2)][]
as.matrix(names(z1))
cat('             
 [1,] "No."             
 [2,] "Date"            
 [3,] "Time"            
 [4,] "Delta"           
 [5,] "Length"          
 [6,] "Source"          
 [7,] "Destination"     
 [8,] "Protocol"        
 [9,] "SrcPort"         
[10,] "DstPort"         
[11,] "Info"            
[12,] "YMD"             
[13,] "HMS"             
[14,] "MS"
')            

#Generic Queries
# Top Talkers
z1[,.N,.(Source, Destination,SrcPort,DstPort,Length)][order(-N)][1:50]
z1[,.N,.(Info)][order(-N)][1:10]
z1[,.N,.(DstPort)][order(-N)][1:10]
z1[,.N,.(SrcPort)][order(-N)][1:10]
z1[is.na(DstPort),.N,.(Destination,DstPort)][order(-N)][1:10]
z1[is.na(SrcPort),.N,.(Source,SrcPort)][order(-N)][1:10]
z1[,.(PcktsPerHour=as.integer(length(No.)/as.integer(last(Date) - first(Date))))][order(-PcktsPerHour)] # Packets per time unit
z1[,.(PcktsPerHour=as.integer(length(No.)/as.integer(last(Date) - first(Date)))),by="DstPort"][order(-PcktsPerHour)] # 
z1[,.(PcktsPerHour=as.integer(length(No.)/as.integer(last(Date) - first(Date)))),by="SrcPort"][order(-PcktsPerHour)] # 
z1[,.(PcktsPerHour=as.integer(length(No.)/as.integer(last(Date) - first(Date)))),by=.(Source,Destination)][order(-PcktsPerHour)]
z1[,.(PcktsPerHour=as.integer(length(No.)/as.integer(last(Date) - first(Date)))),by=.(Protocol,Source)][order(-PcktsPerHour,Protocol,Source)]
z1[,.(PcktsPerHour=as.integer(length(No.)/as.integer(last(Date) - first(Date)))),by=.(Protocol,Source,Destination)][order(-PcktsPerHour,Protocol,Source)]

 
# mux (rbind) together two CSVs;
# negate local subnet traffic from Source field and
# Port 443 traffic from Source or Destination
# based on regex filters in Info field
# Note that muxing two separate CSVs produces (potential) duplicate keys:
# run 'l0[duplicated(No.),.N]'

l0 <- rbind(
fread("07.14.2022.csv")[Protocol == "TCP" &
 (stri_detect_regex(Source,"192.168",negate=TRUE) &
 stri_detect_regex(Info,"443 ",negate=TRUE)),
.(No.,Date,Time,Source,Destination,Info)][order(No.)],

fread("07.15.2022.csv")[Protocol == "TCP" &
 (stri_detect_regex(Destination,"192.168",negate=TRUE) &
 stri_detect_regex(Info,"443 ",negate=TRUE)),
.(No.,Date,Time,Source,Destination,Info)][order(No.)])[order(No.)]

# then look for specific 'Info' characteristics
l0[stri_detect_regex(Info,"Len=0",negate=FALSE),] # "Len=0"
l0[stri_detect_regex(Info,"Len=0",negate=TRUE),]  # not "Len=0"

# track differences in conversations between two different (CSV) packet disections
# Add Conversation and ConvSeq to track separate Conversations 
l1 <- fread("07.14.2022.csv")[order(No.)]
l1[,Conversation:=paste0(Source," -> ",Destination)]
l1 <- l1[, ConvSeq := seq_len(.N),by="Conversation"]
setkey(l1,"No.")
l1_con <- l1[,.(Convl1=.N),.(Conversation)][order(-Convl1)]

l2 <- fread("07.15.2022.csv")[order(No.)]
l2[,Conversation:=paste0(Source," -> ",Destination)]
l2 <- l2[, ConvSeq := seq_len(.N),by="Conversation"]
setkey(l2,"No.")
l2_con <- l2[,.(Convl2=.N),.(Conversation)][order(-Convl2)]

setkey(l1_con,"Conversation")
setkey(l2_con,"Conversation")

# rdata.table;Find A[B]; order by Conversation l1
l_con_table <- l2_con[l1_con,.(Conversation,Convl1,Convl2),by=.EACHI]
setnames(l_con_table,c("Converse1","Converse2","Count1","Count2"))
l_con_table[1:50][order(-Count1)] # top 50 by Count1
l_con_table[1:50][order(-Count2)] # top 50 by Count2

# Using (added fields) of 'Conversation' and 'ConvSeq' to track top counts separate Conversations
ll<- fread("07.14.2022.csv")[order(No.)]
ll[,Conversation:=paste0(Source," -> ",Destination)]
lk <- ll[, ConvSeq := seq_len(.N),by="Conversation"]

#Generic Queries
# Top Talkers
lk[,.N,.(Conversation)][order(-N)]
lk[,.N,.(Source, Destination,SrcPort,DstPort,Length)][order(-N)][1:50]
lk[,.N,.(Info)][order(-N)][1:50]


# track separate Conversations with separate parameters (filters)
lk[Conversation == "AlphaNet_f0:13:29 -> Broadcast",]
lk[Conversation == "204.79.197.219 -> 192.168.0.5",.(Info,ConvSeq)][order(-ConvSeq)]

# three methods to look at conversations from one not using port 443 from Info field
lk[Conversation == "204.79.197.219 -> 192.168.0.5",.(Info,ConvSeq)][
stri_detect_regex(Info,"443 ",negate=TRUE),.(Info,ConvSeq)][order(-ConvSeq)]

lk[Conversation == "204.79.197.219 -> 192.168.0.5",.(Info,Protocol,Length,ConvSeq)][
stri_detect_regex(Info,"443 ",negate=TRUE),.N,.(Info,Protocol,Length)][order(-N)]

lk[Conversation == "204.79.197.219 -> 192.168.0.5",][
stri_detect_regex(Info,"443 ",negate=TRUE),.(No.,Info,Protocol,Length,Conversation,ConvSeq)][order(-ConvSeq)]


