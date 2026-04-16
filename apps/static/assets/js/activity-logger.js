/**
 * RijanAuth Activity Logger
 * Tracks page loads, button clicks, AJAX calls, and form submissions
 * Sends logs to server for console output
 */

class ActivityLogger {
    constructor(options = {}) {
        this.endpoint = options.endpoint || '/api/log';
        this.enableConsole = options.enableConsole !== false;
        this.enableServer = options.enableServer !== false;
        this.userId = options.userId || '';
        this.username = options.username || '';
        this.realm = options.realm || '';
        
        this._originalFetch = window.fetch.bind(window);
        this._initialized = false;
    }

    static instance = null;

    static init(options = {}) {
        if (ActivityLogger.instance) {
            return ActivityLogger.instance;
        }
        
        ActivityLogger.instance = new ActivityLogger(options);
        ActivityLogger.instance._setup();
        
        return ActivityLogger.instance;
    }

    static getInstance() {
        return ActivityLogger.instance;
    }

    _setup() {
        if (this._initialized) return;
        this._initialized = true;

        this._interceptFetch();
        this._setupClickTracking();
        this._setupFormTracking();
        this._trackPageLoad();
    }

    _trackPageLoad() {
        const path = window.location.pathname;
        const title = document.title || 'Untitled';

        this.log({
            type: 'page_load',
            action: path,
            details: {
                title: title,
                referrer: document.referrer || '',
                userAgent: navigator.userAgent.substring(0, 50)
            }
        });
    }

    _setupClickTracking() {
        document.addEventListener('click', (e) => {
            const target = e.target.closest('button, a, [role="button"]');
            if (!target) return;

            const tagName = target.tagName.toLowerCase();
            
            if (tagName === 'a') {
                const href = target.getAttribute('href') || '';
                if (href.startsWith('#') || href.startsWith('javascript')) return;
                return;
            }

            let action = target.textContent.trim() || target.title || target.ariaLabel || 'Unknown';
            action = action.substring(0, 50);

            if (target.classList.contains('btn-delete') ||
                target.classList.contains('btn-danger') ||
                target.getAttribute('data-action') === 'delete' ||
                target.closest('[data-confirm]')) {
                return;
            }

            if (target.type === 'submit') {
                return;
            }

            this.log({
                type: 'button_click',
                action: action,
                target: target.id || target.className.split(' ')[0] || 'unnamed',
                page: this._getCurrentPage()
            });
        }, true);
    }

    _setupFormTracking() {
        document.addEventListener('submit', (e) => {
            const form = e.target;
            const formId = form.id || form.className.split(' ')[0] || 'unnamed';
            let formName = form.name || formId;

            const submitBtn = form.querySelector('[type="submit"]:focus') ||
                             form.querySelector('[type="submit"]');
            const btnText = submitBtn ? (submitBtn.textContent.trim() || submitBtn.value) : 'Submit';
            btnText.substring(0, 30);

            this.log({
                type: 'form_submit',
                action: formName,
                form: formId,
                page: this._getCurrentPage(),
                details: {
                    method: form.method.toUpperCase(),
                    action: form.action
                }
            });
        }, true);
    }

    _interceptFetch() {
        const self = this;

        window.fetch = function(url, options = {}) {
            const fetchOptions = options;
            const method = fetchOptions.method || 'GET';
            const startTime = Date.now();

            return self._originalFetch.call(window, url, fetchOptions)
                .then(response => {
                    const duration = Date.now() - startTime;
                    const status = response.status;
                    const urlStr = typeof url === 'string' ? url : url.url || url.toString();

                    if (self._shouldLogUrl(urlStr)) {
                        self.log({
                            type: 'ajax',
                            method: method,
                            url: urlStr,
                            status: status,
                            duration: duration,
                            details: {
                                realm: self.realm
                            }
                        });
                    }

                    return response;
                })
                .catch(error => {
                    const urlStr = typeof url === 'string' ? url : url.url || url.toString();

                    if (self._shouldLogUrl(urlStr)) {
                        self.log({
                            type: 'ajax',
                            method: method,
                            url: urlStr,
                            status: 0,
                            error: error.message,
                            details: {
                                realm: self.realm
                            }
                        });
                    }

                    throw error;
                });
        };
    }

    _shouldLogUrl(url) {
        const excludePatterns = [
            '/api/health',
            '/api/log',
            '/media/',
            '.css',
            '.js',
            '.png',
            '.jpg',
            '.svg',
            '.ico'
        ];

        return !excludePatterns.some(pattern => url.includes(pattern));
    }

    _getCurrentPage() {
        const path = window.location.pathname;
        const matches = path.match(/\/admin\/[^/]+\/([^/]+)/);
        return matches ? matches[1] : path.split('/').pop() || 'dashboard';
    }

    log(data) {
        const payload = {
            type: data.type,
            action: data.action,
            username: this.username,
            realm: this.realm,
            target: data.target,
            page: data.page,
            method: data.method,
            url: data.url,
            status: data.status,
            form: data.form,
            details: data.details || {}
        };

        if (this.enableConsole) {
            this._consoleLog(payload);
        }

        if (this.enableServer) {
            this._sendToServer(payload);
        }
    }

    _consoleLog(payload) {
        const type = payload.type;
        const style = this._getConsoleStyle(type);

        switch (type) {
            case 'page_load':
                console.log(`%c[BROWSER] ${this.username} loaded ${payload.action}`, style);
                break;
            case 'button_click':
                console.log(`%c[BROWSER] ${this.username} clicked "${payload.action}" @ ${payload.page}`, style);
                break;
            case 'ajax':
                const statusColor = payload.status >= 400 ? 'color: red' : 'color: green';
                console.log(`%c[BROWSER] ${this.username} AJAX ${payload.method} ${payload.url} -> %c${payload.status}%c ${payload.duration}ms`,
                    style, statusColor, style);
                break;
            case 'form_submit':
                console.log(`%c[BROWSER] ${this.username} submitted form "${payload.action}" @ ${payload.page}`, style);
                break;
            default:
                console.log(`%c[BROWSER] ${payload.action}`, style);
        }
    }

    _getConsoleStyle(type) {
        const styles = {
            'page_load': 'color: #9b59b6',
            'button_click': 'color: #3498db',
            'ajax': 'color: #e67e22',
            'form_submit': 'color: #1abc9c'
        };
        return styles[type] || 'color: #95a5a6';
    }

    _sendToServer(payload) {
        try {
            this._originalFetch.call(window, this.endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload),
                keepalive: true
            }).catch(() => {});
        } catch (e) {}
    }
}

window.ActivityLogger = ActivityLogger;
