package main

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"os"
	//  _ "github.com/jinzhu/gorm/dialects/postgres"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	//  _ "github.com/jinzhu/gorm/dialects/mssql"
	"fmt"
)

// User ...
/*type User struct {
	ID       uint
	Username string
	Password string
}*/

var db *gorm.DB

func dbInit() {
	var err error
	// Switch database
	fmt.Printf("Open db connection: %q : %q\n", os.Getenv("MYSQL_DATABASE"), os.Getenv("MYSQL_USER")+":"+os.Getenv("MYSQL_PASSWORD")+"@tcp("+os.Getenv("DOCKER_DB_CONTAINER_NAME")+")/"+os.Getenv("MYSQL_DATABASE")+"?charset=utf8&parseTime=True&loc=Local")
	if os.Getenv("MYSQL_DATABASE") != "" {
		//db, err = gorm.Open("mysql", os.Getenv("MYSQL_USER")+":"+os.Getenv("MYSQL_PASSWORD")+"@tcp("+os.Getenv("MYSQL_ROOT_HOST")+":"+os.Getenv("MYSQL_PORT")+")/"+os.Getenv("MYSQL_DATABASE")+"?charset=utf8&parseTime=True&loc=Local")
		db, err = gorm.Open("mysql", os.Getenv("MYSQL_USER")+":"+os.Getenv("MYSQL_PASSWORD")+"@tcp("+os.Getenv("DOCKER_DB_CONTAINER_NAME")+")/"+os.Getenv("MYSQL_DATABASE")+"?charset=utf8&parseTime=True&loc=Local")
	}
	if err != nil {
		fmt.Printf("Error connecting to db: %q\n", err)
		db, err = gorm.Open("sqlite3", "/data/soundscape.db")
		if err != nil {
			fmt.Printf("Error connecting to db: %q\n", err)
			panic("failed to connect database")
		}
	}
	//defer db.Close()
	db.SingularTable(true)
	//db.AutoMigrate(&User{})
	db.AutoMigrate(&Media{})
	db.AutoMigrate(&List{})
	db.AutoMigrate(&User{})

	// Add / verify foreign keys
	//db.Exec("ALTER TABLE `list_media` ADD CONSTRAINT `fk_list_id` FOREIGN KEY (`list_id`) REFERENCES `list` (`id`) ON UPDATE CASCADE ON DELETE CASCADE, ADD CONSTRAINT `fk_media_id` FOREIGN KEY (`media_id`) REFERENCES `media` (`id`) ON UPDATE CASCADE ON DELETE CASCADE;")
}
