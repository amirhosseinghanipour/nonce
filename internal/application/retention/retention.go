package retention

import (
	"context"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
)

// RunAnonymizeDeletedUsers finds users soft-deleted before (now - anonymizeAfterDays) and anonymizes their PII.
// Call periodically (e.g. daily cron). anonymizeAfterDays 0 = no-op.
func RunAnonymizeDeletedUsers(ctx context.Context, userRepo ports.UserRepository, anonymizeAfterDays int) (anonymized int, err error) {
	if anonymizeAfterDays <= 0 {
		return 0, nil
	}
	threshold := time.Now().Add(-time.Duration(anonymizeAfterDays) * 24 * time.Hour)
	refs, err := userRepo.ListDeletedBefore(ctx, threshold)
	if err != nil {
		return 0, err
	}
	for _, ref := range refs {
		if e := userRepo.Anonymize(ctx, ref.ProjectID, ref.UserID); e != nil {
			return anonymized, e // stop on first error
		}
		anonymized++
	}
	return anonymized, nil
}
