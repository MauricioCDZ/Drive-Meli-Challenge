use db;

CREATE TABLE Drivefile(
    ID integer not null AUTO_INCREMENT,
    FileID varchar(100) NOT NULL,
    NameFile varchar(100) NOT NULL,
    Extension varchar(100) NOT NULL,
    OwnerName varchar(100) NOT NULL,
    Visibility varchar(100) NOT NULL,
    LastModDate varchar(100) NOT NULL,
    WasPublic Boolean NOT NULL DEFAULT false,

    UNIQUE(FileID),
    PRIMARY KEY (ID)
);


--INSERT INTO Drivefile(FileID,NameFile,Extension,OwnerName,Visibility,LastModDate,WasPublic) 
--VALUES ("1jiCxACZ8vSSEJES1Rm9RszXlL0c_HGg3HuIbDd3suQX","Andersen",".txt","mauricio cortes","Public","ayer xD",true),
--("1jiCxACZ8vSSEJES1Rm9RszXlL0c_HGg3HuIbDd3suQV","Andersen sizas",".csv","mauricio diaz","Private","hoy xD",false);