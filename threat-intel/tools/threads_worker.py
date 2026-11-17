#!/usr/bin/env python3
"""Publish one approved, due Threads carousel from the local social_queue.

Requires python3-psycopg2 and ~/.config/1dotq/threads-token. Does not approve
or schedule posts. On any failure, leaves status=failed for manual review.
"""
import json
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

import psycopg2
from psycopg2.extras import RealDictCursor

API = 'https://graph.threads.net/v1.0'
TOKEN_PATH = Path.home() / '.config/1dotq/threads-token'


def api_request(token, method, path, fields=None):
    data = urlencode(fields or {}).encode('utf-8') if method == 'POST' else None
    req = Request(API + path, data=data, method=method,
                  headers={'Authorization': 'Bearer ' + token})
    try:
        with urlopen(req, timeout=30) as response:
            result = json.load(response)
    except HTTPError as exc:
        raise RuntimeError('Threads API returned HTTP ' + str(exc.code)) from None
    except (URLError, TimeoutError, OSError, ValueError) as exc:
        raise RuntimeError('Threads API request failed: ' + type(exc).__name__) from None
    if not isinstance(result, dict):
        raise RuntimeError('Threads API returned an unexpected response')
    return result


def wait_for_media(token, container_id):
    for _ in range(15):
        response = api_request(token, 'GET', '/' + container_id + '?fields=status')
        status = response.get('status')
        if status in ('FINISHED', 'PUBLISHED'):
            return
        if status in ('ERROR', 'EXPIRED'):
            raise RuntimeError('Media container status: ' + status)
        time.sleep(2)
    raise RuntimeError('Media container was not ready within 30 seconds')


def main():
    token = TOKEN_PATH.read_text(encoding='utf-8').strip()
    if not token:
        raise RuntimeError('Threads token file is empty')
    conn = psycopg2.connect(dbname='threat_intel')
    try:
        # Claim atomically. Mark failed BEFORE external calls: a crash or a lost
        # publish response must never cause an automatic duplicate post.
        with conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                  UPDATE social_queue SET status='failed', updated_at=now(),
                    last_error='Attempt started; check Threads before retrying.'
                  WHERE id = (
                    SELECT id FROM social_queue
                    WHERE platform='threads' AND status='approved'
                      AND scheduled_at IS NOT NULL AND scheduled_at <= now()
                    ORDER BY scheduled_at, id
                    FOR UPDATE SKIP LOCKED LIMIT 1
                  ) RETURNING id, caption, media_paths
                """)
                job = cur.fetchone()
        if not job:
            print('No approved Threads posts are due.')
            return
        job_id = job['id']
        try:
            caption = job['caption'] or ''
            urls = job['media_paths']
            if not isinstance(urls, list) or not 2 <= len(urls) <= 20:
                raise RuntimeError('A carousel must have 2–20 image URLs')
            if not caption.strip() or len(caption) > 500:
                raise RuntimeError('Threads caption must contain 1–500 characters')
            for url in urls:
                parsed = urlparse(url) if isinstance(url, str) else None
                if not parsed or parsed.scheme != 'https' or parsed.hostname != '1dotq.github.io' or parsed.username or parsed.password:
                    raise RuntimeError('Images must use public HTTPS URLs on 1dotq.github.io')
            children = []
            for url in urls:
                response = api_request(token, 'POST', '/me/threads', {
                    'media_type': 'IMAGE', 'image_url': url, 'is_carousel_item': 'true',
                })
                child = response.get('id')
                if not isinstance(child, str) or not child.isdigit():
                    raise RuntimeError('No valid image container ID returned')
                wait_for_media(token, child)
                children.append(child)
            response = api_request(token, 'POST', '/me/threads', {
                'media_type': 'CAROUSEL', 'children': ','.join(children), 'text': caption,
            })
            parent = response.get('id')
            if not isinstance(parent, str) or not parent.isdigit():
                raise RuntimeError('No valid carousel container ID returned')
            wait_for_media(token, parent)
            # From here, a timeout can mean success or failure. Never auto retry.
            response = api_request(token, 'POST', '/me/threads_publish', {'creation_id': parent})
            post_id = response.get('id')
            if not isinstance(post_id, str) or not post_id.isdigit():
                raise RuntimeError('Publish response did not include a valid post ID')
            with conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE social_queue SET status='published', published_at=now(), platform_post_id=%s, last_error=NULL, updated_at=now() WHERE id=%s", (post_id, job_id))
            print('Published queue item', job_id, 'as Threads post', post_id)
        except Exception as exc:
            with conn:
                with conn.cursor() as cur:
                    cur.execute('UPDATE social_queue SET last_error=%s, updated_at=now() WHERE id=%s',
                                (str(exc)[:400] + ' Check Threads before retrying.', job_id))
            print('Queue item', job_id, 'needs manual review:', exc, file=sys.stderr)
            sys.exit(1)
    finally:
        conn.close()


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('Worker could not start:', type(exc).__name__, file=sys.stderr)
        sys.exit(1)

