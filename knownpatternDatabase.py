from cs50 import SQL
from categories import category
db = SQL("sqlite:///elibrary.db")
i = 0
#db.execute("Drop table knownpatterns")

#Creating a known pattern database(Table)
db.execute("CREATE table knownpatterns(knownpatterns TEXT NOT NULL,category TEXT )")
#Adding categories into table
for line in open('knownpatterns.txt', "r"):
   cate = category(str(line.rstrip('\n')))
   db.execute("INSERT INTO knownpatterns (knownpatterns, category) VALUES (?,?)",line.rstrip('\n'),cate)
   print(i)
   i+=1
db.execute("Update knownpatterns set category = 'Tautology' where knownpatterns LIKE ? AND knownpatterns Not like ? ",'%' + "admin"+ '%','%' + "union"+ '%')

    