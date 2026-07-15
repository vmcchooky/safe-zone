package main

import (
	"context"
	"fmt"
	"log"
	"safe-zone/internal/store"
)

func main() {
	db, err := store.New("D:\\Quorix\\services\\safe-zone\\data\\safe-zone.db", 30)
	if err != nil {
		log.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	reports, err := db.ListBlockReportsFiltered(context.Background(), store.BlockReportFilter{Status: "pending"}, 100, 0)
	if err != nil {
		log.Fatalf("failed to list: %v", err)
	}

	fmt.Printf("Found %d pending reports\n", len(reports))
	for _, r := range reports {
		fmt.Printf("- %s: %s\n", r.Domain, r.Status)
	}
}
