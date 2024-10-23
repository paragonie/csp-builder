<?php
declare(strict_types=1);
namespace ParagonIE\CSPBuilder;

use Opis\JsonSchema\Exceptions\SchemaException;
use Opis\JsonSchema\Helper;
use Opis\JsonSchema\Validator;
use ParagonIE\ConstantTime\Base64;
use Psr\Http\Message\MessageInterface;
use Exception;
use RuntimeException;
use TypeError;
use function array_keys;
use function file_exists;
use function file_get_contents;
use function file_put_contents;
use function filter_var;
use function hash;
use function header;
use function headers_sent;
use function implode;
use function in_array;
use function is_array;
use function is_string;
use function json_encode;
use function json_decode;
use function preg_replace;
use function random_bytes;
use function rtrim;
use function str_replace;
use function strpos;

/**
 * Class CSPBuilder
 * @package ParagonIE\CSPBuilder
 */
class CSPBuilder
{
    const FORMAT_APACHE = 'apache';
    const FORMAT_NGINX = 'nginx';

    /**
     * @var array<array-key, mixed>
     */
    private $policies = [];

    /**
     * @var array<int, string>
     */
    private $requireSRIFor = [];

    /**
     * @var bool
     */
    private $needsCompile = true;

    /**
     * @var string
     */
    private $compiled = '';

    /**
     * @var array
     */
    private $reportEndpoints = [];

    /**
     * @var string
     */
    private $compiledEndpoints = '';

    /**
     * @var bool
     */
    private $needsCompileEndpoints = true;

    /**
     * @var bool
     */
    private $reportOnly = false;

    /**
     * @var bool
     */
    protected $supportOldBrowsers = true;

    /**
     * @var bool
     */
    protected $httpsTransformOnHttpsConnections = true;

    /**
     * @var string[]
     */
    private static $directives = [
        'base-uri',
        'default-src',
        'child-src',
        'connect-src',
        'font-src',
        'form-action',
        'frame-ancestors',
        'frame-src',
        'img-src',
        'media-src',
        'object-src',
        'plugin-types',
        'manifest-src',
        'sandbox',
        'script-src',
        'script-src-elem',
        'script-src-attr',
        'style-src',
        'style-src-elem',
        'style-src-attr',
        'worker-src'
    ];

    /**
     * @param array $policy
     */
    public function __construct(array $policy = [])
    {
        $this->policies = $policy;
    }

    /**
     * Compile the current policies into a CSP header
     *
     * @return string
     * @throws TypeError
     */
    public function compile(): string
    {
        $ruleKeys = array_keys($this->policies);
        if (in_array('report-only', $ruleKeys)) {
            $this->reportOnly = !!$this->policies['report-only'];
        } else {
            $this->reportOnly = false;
        }

        $compiled = [];

        foreach (self::$directives as $dir) {
            if (in_array($dir, $ruleKeys)) {
                if (empty($ruleKeys)) {
                    if ($dir === 'base-uri') {
                        continue;
                    }
                }
                $compiled []= $this->compileSubgroup(
                    $dir,
                    $this->policies[$dir]
                );
            }
        }

        if (!empty($this->policies['report-uri'])) {
            if (!is_string($this->policies['report-uri'])) {
                throw new TypeError('report-uri policy somehow not a string');
            }
            $compiled []= sprintf(
                'report-uri %s; ',
                $this->enc($this->policies['report-uri'], 'report-uri')
            );
        }
        if (!empty($this->policies['report-to'])) {
            if (!is_string($this->policies['report-to'])) {
                throw new TypeError('report-to policy somehow not a string');
            }
            // @todo validate this `report-to` target, is in the `report-to` header?
            $compiled[] = sprintf('report-to %s; ', $this->policies['report-to']);
        }
        if (!empty($this->policies['upgrade-insecure-requests'])) {
            $compiled []= 'upgrade-insecure-requests';
        }

        $this->compiled = rtrim(implode('', $compiled), '; ');
        $this->needsCompile = false;

        return $this->compiled;
    }

    /**
     * @psalm-suppress DocblockTypeContradiction
     * @psalm-suppress TypeDoesNotContainType
     */
    public function compileReportEndpoints(): string
    {
        if (!empty($this->reportEndpoints) && $this->needsCompileEndpoints) {
            // If it's a string, it's probably something like `report-to: key=endpoint
            // Do nothing
            if (!is_array($this->reportEndpoints)) {
                throw new TypeError('Report endpoints is not an array');
            }

            $jsonValidator = new Validator();
            $reportTo = [];
            $schema = file_get_contents(__DIR__ . '/../schema/reportto.json');
            foreach ($this->reportEndpoints as $reportEndpoint) {
                $reportEndpointAsJSON = \Opis\JsonSchema\Helper::toJSON($reportEndpoint);
                $isValid = $jsonValidator->validate($reportEndpointAsJSON, $schema);
                if ($isValid->isValid()) {
                    $reportTo[] = json_encode($reportEndpointAsJSON);
                }
            }
            $this->compiledEndpoints = rtrim(implode(',', $reportTo));
            $this->needsCompileEndpoints = false;
        }
        return $this->compiledEndpoints;
    }

    /**
     * Add a source to our allow white-list
     *
     * @param string $directive
     * @param string $path
     *
     * @return self
     */
    public function addSource(string $directive, string $path): self
    {
        $this->needsCompile = true;
        switch ($directive) {
            case 'child':
            case 'child-src':
                if ($this->supportOldBrowsers) {
                    $this->policies['child-src']['allow'][] = $path;
                    $this->policies['frame-src']['allow'][] = $path;
                    return $this;
                }
                $directive = 'child-src';
                break;
            case 'frame':
            case 'frame-src':
                if ($this->supportOldBrowsers) {
                    $this->policies['child-src']['allow'][] = $path;
                    $this->policies['frame-src']['allow'][] = $path;
                    return $this;
                }
                $directive = 'frame-src';
                break;
            case 'connect':
            case 'socket':
            case 'websocket':
                $directive = 'connect-src';
                break;
            case 'font':
            case 'fonts':
                $directive = 'font-src';
                break;
            case 'form':
            case 'forms':
                $directive = 'form-action';
                break;
            case 'ancestor':
            case 'parent':
                $directive = 'frame-ancestors';
                break;
            case 'img':
            case 'image':
            case 'image-src':
                $directive = 'img-src';
                break;
            case 'media':
                $directive = 'media-src';
                break;
            case 'object':
                $directive = 'object-src';
                break;
            case 'js':
            case 'javascript':
            case 'script':
            case 'scripts':
                $directive = 'script-src';
                break;
            case 'style':
            case 'css':
            case 'css-src':
                $directive = 'style-src';
                break;
            case 'worker':
                $directive = 'worker-src';
                break;
        }
        if (!isset($this->policies[$directive])) {
            $this->policies[$directive] = [];
        }
        if (!isset($this->policies[$directive]['allow'])) {
            $this->policies[$directive]['allow'] = [];
        }
        if (is_array($this->policies[$directive]['allow'])) {
            if (!in_array($path, $this->policies[$directive]['allow'], true)) {
                $this->policies[$directive]['allow'][] = $path;
            }
        }
        return $this;
    }

    /**
     * Add a directive if it doesn't already exist
     *
     * If it already exists, do nothing
     *
     * @param string $key
     * @param mixed $value
     *
     * @return self
     */
    public function addDirective(string $key, $value = null): self
    {
        $this->needsCompile = true;
        if ($value === null) {
            if (!isset($this->policies[$key])) {
                $this->policies[$key] = true;
            }
        } elseif (empty($this->policies[$key])) {
            $this->policies[$key] = $value;
        }
        return $this;
    }


    /**
     * @param array|string $reportEndpoint
     * @return void
     */
    public function addReportEndpoints($reportEndpoint): void
    {
        $this->needsCompileEndpoints = true;
        $this->reportEndpoints[] = Helper::toJSON($reportEndpoint);
    }

    /**
     * Add a plugin type to be added
     *
     * @param string $mime
     * @return self
     */
    public function allowPluginType(string $mime = 'text/plain'): self
    {
        $this->policies['plugin-types']['types'] []= $mime;

        $this->needsCompile = true;
        return $this;
    }

    /**
     * Disable old browser support (e.g. Safari)
     *
     * @return self
     */
    public function disableOldBrowserSupport(): self
    {
        $this->needsCompile = ($this->needsCompile || $this->supportOldBrowsers !== false);
        $this->supportOldBrowsers = false;
        return $this;
    }

    /**
     * Enable old browser support (e.g. Safari)
     *
     * This is enabled by default
     *
     * @return self
     */
    public function enableOldBrowserSupport(): self
    {
        $this->needsCompile = ($this->needsCompile || $this->supportOldBrowsers !== true);
        $this->supportOldBrowsers = true;
        return $this;
    }

    /**
     * This just passes the array to the constructor, but hopefully will save
     * someone in a hurry from a moment of frustration.
     *
     * @param array $array
     * @return self
     */
    public static function fromArray(array $array = []): self
    {
        return new CSPBuilder($array);
    }

    /**
     * Factory method - create a new CSPBuilder object from JSON data
     *
     * @param string $data
     * @return self
     * @throws Exception
     */
    public static function fromData(string $data = ''): self
    {
        $array = json_decode($data, true);

        if (!is_array($array)) {
            throw new Exception('Is not array valid');
        }

        return new CSPBuilder($array);
    }

    /**
     * Factory method - create a new CSPBuilder object from a JSON file
     *
     * @param string $filename
     * @return self
     * @throws Exception
     */
    public static function fromFile(string $filename = ''): self
    {
        if (!file_exists($filename)) {
            throw new Exception($filename.' does not exist');
        }
        $contents = file_get_contents($filename);
        if (!is_string($contents)) {
            throw new Exception('Could not read file contents');
        }
        return self::fromData($contents);
    }

    /**
     * Factory method - create a new CSPBuilder object from an existing CSP header
     *
     * @param string $header
     * @return self
     * @throws Exception
     *
     * @psalm-suppress DocblockTypeContradiction
     */
    public static function fromHeader(string $header = ''): self
    {
        $csp = new CSPBuilder();

        $directives = explode(';', $header);

        foreach ($directives as $directive) {
            [$name, $values] = explode(' ', trim($directive), 2) + [null, null];

            if (is_null($name)) {
                continue;
            }

            if ('upgrade-insecure-requests' === $name) {
                $csp->addDirective('upgrade-insecure-requests');

                continue;
            }

            if (null === $values) {
                continue;
            }

            foreach (explode(' ', $values) as $value) {
                if ('report-to' === $name) {
                    $csp->setReportTo($value);
                } elseif ('report-uri' === $name) {
                    $csp->setReportUri($value);
                } elseif ('require-sri-for' === $name) {
                    $csp->requireSRIFor($value);
                } elseif ('plugin-types' === $name) {
                    $csp->allowPluginType($value);
                } else {
                    switch ($value) {
                        case "'none'": $csp->addDirective($name, false); break;
                        case "'self'": $csp->setSelfAllowed($name, true); break;
                        case 'blob:': $csp->setBlobAllowed($name, true); break;
                        case 'data:': $csp->setDataAllowed($name, true); break;
                        case 'filesystem:': $csp->setFileSystemAllowed($name, true); break;
                        case 'https:': $csp->setHttpsAllowed($name, true); break;
                        case 'mediastream:': $csp->setMediaStreamAllowed($name, true); break;
                        case "'report-sample'": $csp->setReportSample($name, true); break;
                        case "'strict-dynamic'": $csp->setStrictDynamic($name, true); break;
                        case "'unsafe-eval'": $csp->setAllowUnsafeEval($name, true); break;
                        case "'unsafe-hashes'": $csp->setAllowUnsafeHashes($name, true); break;
                        case "'unsafe-inline'": $csp->setAllowUnsafeInline($name, true); break;
                        case "'unsafe-hashed-attributes'": $csp->setAllowUnsafeHashedAttributes('script-src', true); break;

                        default: $csp->addSource($name, $value);
                    }
                }
            }
        }

        return $csp;
    }

    /**
     * Get the formatted CSP header
     *
     * @return string
     */
    public function getCompiledHeader(): string
    {
        if ($this->needsCompile) {
            $this->compile();
        }
        return $this->compiled;
    }

    /**
     * Get the formatted report-to header
     *
     * @return string
     */
    public function getCompiledReportEndpointsHeader(): string
    {
        if ($this->needsCompileEndpoints) {
            $this->compileReportEndpoints();
        }

        return $this->compiledEndpoints;
    }

    /**
     * Get an associative array of headers to return.
     *
     * @param bool $legacy
     * @return array<string, string>
     */
    public function getHeaderArray(bool $legacy = true): array
    {
        $return = [];
        if ($this->needsCompile) {
            $this->compile();
        }
        if ($this->needsCompileEndpoints) {
            $this->compileReportEndpoints();
        }
        if (!empty($this->compiledEndpoints)) {
            $return = [
                'Report-To' => $this->compiledEndpoints
            ];
        }
        foreach ($this->getHeaderKeys($legacy) as $key) {
            $return[(string) $key] = $this->compiled;
        }
        return $return;
    }

    /**
     * @return array<int, array{0:string, 1:string}>
     */
    public function getRequireHeaders(): array
    {
        $headers = [];
        foreach ($this->requireSRIFor as $directive) {
            $headers[] = [
                'Content-Security-Policy',
                'require-sri-for ' . $directive
            ];
        }
        return $headers;
    }

    /**
     * @return array
     */
    public function getReportEndpoints(): array
    {
        return $this->reportEndpoints;
    }

    /**
     * Add a new hash to the existing CSP
     *
     * @param string $directive
     * @param string $script
     * @param string $algorithm
     * @return self
     */
    public function hash(
        string $directive = 'script-src',
        string $script = '',
        string $algorithm = 'sha384'
    ): self {
        $ruleKeys = array_keys($this->policies);
        if (in_array($directive, $ruleKeys)) {
            $this->policies[$directive]['hashes'] []= [
                $algorithm => Base64::encode(
                    hash($algorithm, $script, true)
                )
            ];
        }
        return $this;
    }

    /**
     * PSR-7 header injection.
     *
     * This will inject the header into your PSR-7 object. (Request, Response,
     * etc.) This method returns an instance of whatever you passed, so long
     * as it implements MessageInterface.
     *
     * @param MessageInterface $message
     * @param bool $legacy
     * @return MessageInterface
     */
    public function injectCSPHeader(MessageInterface $message, bool $legacy = false): MessageInterface
    {
        if ($this->needsCompile) {
            $this->compile();
        }
        if ($this->needsCompileEndpoints) {
            $this->compileReportEndpoints();
        }
        foreach ($this->getRequireHeaders() as $header) {
            list ($key, $value) = $header;
            $message = $message->withAddedHeader($key, $value);
        }
        foreach ($this->getHeaderKeys($legacy) as $key) {
            $message = $message->withAddedHeader($key, $this->compiled);
        }
        if (!empty($this->compileReportEndpoints())) {
            $message = $message->withAddedHeader('report-to', $this->compiledEndpoints);
        }

        return $message;
    }

    /**
     * Add a new nonce to the existing CSP. Returns the nonce generated.
     *
     * @param string $directive
     * @param string $nonce (if empty, it will be generated)
     * @return string
     * @throws Exception
     */
    public function nonce(string $directive = 'script-src', string $nonce = ''): string
    {
        $ruleKeys = array_keys($this->policies);
        if (!in_array($directive, $ruleKeys) && !in_array('default-src', $ruleKeys)) {
            return '';
        }

        if (empty($nonce)) {
            $nonce = Base64::encode(random_bytes(18));
        }
        $this->policies[$directive]['nonces'] []= $nonce;
        return $nonce;
    }

    /**
     * Add a new (pre-calculated) base64-encoded hash to the existing CSP
     *
     * @param string $directive
     * @param string $hash
     * @param string $algorithm
     * @return self
     */
    public function preHash(
        string $directive = 'script-src',
        string $hash = '',
        string $algorithm = 'sha384'
    ): self {
        $ruleKeys = array_keys($this->policies);
        if (in_array($directive, $ruleKeys)) {
            $this->policies[$directive]['hashes'] []= [
                $algorithm => $hash
            ];
        }
        return $this;
    }

    /**
     * @param string $directive
     * @return self
     */
    public function requireSRIFor(string $directive): self
    {
        if (!in_array($directive, $this->requireSRIFor, true)) {
            $this->requireSRIFor[] = $directive;
        }
        return $this;
    }

    /**
     * Save CSP to a snippet file
     *
     * @param string $outputFile Output file name
     * @param string $format Which format are we saving in?
     * @return bool
     * @throws Exception
     */
    public function saveSnippet(
        string $outputFile,
        string $format = self::FORMAT_NGINX,
        ?callable $hookBeforeSave = null
    ): bool {
        if ($this->needsCompile) {
            $this->compile();
            $this->compileReportEndpoints();
        }

        // Are we doing a report-only header?
        $which = $this->reportOnly
            ? 'Content-Security-Policy-Report-Only'
            : 'Content-Security-Policy';

        switch ($format) {
            case self::FORMAT_NGINX:
                // In PHP < 7, implode() is faster than concatenation
                $output = implode('', [
                    'add_header ',
                    $which,
                    ' "',
                    rtrim($this->compiled, ' '),
                    '" always;',
                    "\n"
                ]);
                break;
            case self::FORMAT_APACHE:
                $output = implode('', [
                    'Header add ',
                    $which,
                    ' "',
                    rtrim($this->compiled, ' '),
                    '"',
                    "\n"
                ]);
                break;
            default:
                throw new Exception('Unknown format: '.$format);
        }

        if ($hookBeforeSave !== null) {
            $output = $hookBeforeSave($output);
        }

        return file_put_contents($outputFile, $output) !== false;
    }

    /**
     * Send the compiled CSP as a header()
     *
     * @param bool $legacy Send legacy headers?
     *
     * @return bool
     * @throws Exception
     */
    public function sendCSPHeader(bool $legacy = true): bool
    {
        if (headers_sent()) {
            throw new Exception('Headers already sent!');
        }
        if ($this->needsCompile) {
            $this->compile();
        }
        if ($this->needsCompileEndpoints) {
            $this->compileReportEndpoints();
        }
        foreach ($this->getRequireHeaders() as $header) {
            list ($key, $value) = $header;
            header(sprintf('%s: %s', $key, $value));
        }
        foreach ($this->getHeaderKeys($legacy) as $key) {
            header(sprintf('%s: %s', $key, $this->compiled));
        }
        if (!empty($this->compiledEndpoints)) {
            header(sprintf('report-to: %s', $this->compiledEndpoints));
        }
        return true;
    }

    /**
     * Allow/disallow unsafe-eval within a given directive.
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws Exception
     */
    public function setAllowUnsafeEval(string $directive = '', bool $allow = false): self
    {
        if (!in_array($directive, self::$directives)) {
            throw new Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['unsafe-eval'] = $allow;
        return $this;
    }

    /**
     * Allow/disallow unsafe-inline within a given directive.
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws Exception
     */
    public function setAllowUnsafeInline(string $directive = '', bool $allow = false): self
    {
        if (!in_array($directive, self::$directives)) {
            throw new Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['unsafe-inline'] = $allow;
        return $this;
    }

    /**
     * Allow/disallow unsafe-hashed-attributes within a given directive.
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws Exception
     */
    public function setAllowUnsafeHashedAttributes(string $directive = '', bool $allow = false): self
    {
        if (!in_array($directive, self::$directives)) {
            throw new Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['unsafe-hashed-attributes'] = $allow;
        return $this;
    }

    /**
     * Allow/disallow blob: URIs for a given directive
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws Exception
     */
    public function setBlobAllowed(string $directive = '', bool $allow = false): self
    {
        if (!in_array($directive, self::$directives)) {
            throw new Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['blob'] = $allow;
        return $this;
    }

    /**
     * Allow/disallow data: URIs for a given directive
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws Exception
     */
    public function setDataAllowed(string $directive = '', bool $allow = false): self
    {
        if (!in_array($directive, self::$directives)) {
            throw new Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['data'] = $allow;
        return $this;
    }

    /**
     * Set a directive.
     *
     * This lets you overwrite a complex directive entirely (e.g. script-src)
     * or set a top-level directive (e.g. report-uri).
     *
     * @param string $key
     * @param mixed $value
     *
     * @return self
     */
    public function setDirective(string $key, $value = []): self
    {
        $this->policies[$key] = $value;
        return $this;
    }

    /**
     * Removes a directive.
     *
     * This allows removing a directive if the presence of it might cause
     * undesired behavioral changes.
     *
     * @param string $key
     *
     * @return self
     */
    public function removeDirective(string $key): self
    {
        unset($this->policies[$key]);
        return $this;
    }

    /**
     * @param array|string $reportEndpoints
     * @return void
     */
    public function setReportEndpoints($reportEndpoints): void
    {
        $this->needsCompileEndpoints = true;
        $toJSON = Helper::toJSON($reportEndpoints);
        // If there's only one, wrap it in an array, so more can be added
        $toJSON = is_array($toJSON) ? $toJSON : [$toJSON];
        $this->reportEndpoints = $toJSON;
    }

    /**
     * @param string $key
     * @return void
     */
    public function removeReportEndpoint(string $key): void
    {
        foreach ($this->reportEndpoints as $idx => $endpoint) {
            if ($endpoint->group === $key) {
                unset($this->reportEndpoints[$idx]);
                // Reset the array keys
                $this->reportEndpoints = array_values($this->reportEndpoints);
                break;
            }
        }
    }
    /**
     * Allow/disallow filesystem: URIs for a given directive
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws Exception
     */
    public function setFileSystemAllowed(string $directive = '', bool $allow = false): self
    {
        if (!in_array($directive, self::$directives)) {
            throw new Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['filesystem'] = $allow;
        return $this;
    }

    /**
     * Allow/disallow mediastream: URIs for a given directive
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws Exception
     */
    public function setMediaStreamAllowed(string $directive = '', bool $allow = false): self
    {
        if (!in_array($directive, self::$directives)) {
            throw new Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['mediastream'] = $allow;
        return $this;
    }

    /**
     * Allow/disallow loading resources only over HTTPS on any domain for a given directive
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws Exception
     */
    public function setHttpsAllowed(string $directive = '', bool $allow = false): self
    {
        if (!in_array($directive, self::$directives)) {
            throw new Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['https'] = $allow;
        return $this;
    }

    /**
     * Allow/disallow self URIs for a given directive
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws Exception
     */
    public function setSelfAllowed(string $directive = '', bool $allow = false): self
    {
        if (!in_array($directive, self::$directives)) {
            throw new Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['self'] = $allow;
        return $this;
    }

    /**
     * @see CSPBuilder::setAllowUnsafeEval()
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws Exception
     */
    public function setUnsafeEvalAllowed(string $directive = '', bool $allow = false): self
    {
        return $this->setAllowUnsafeEval($directive, $allow);
    }

    /**
     * Allow/disallow unsafe-hashes within a given directive.
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws Exception
     */
    public function setAllowUnsafeHashes(string $directive = '', bool $allow = false): self
    {
        if (!in_array($directive, self::$directives)) {
            throw new Exception('Directive ' . $directive . ' does not exist');
        }
        $this->policies[$directive]['unsafe-hashes'] = $allow;
        return $this;
    }

    /**
     * @see CSPBuilder::setAllowUnsafeInline()
     *
     * @param string $directive
     * @param bool $allow
     * @return self
     * @throws Exception
     */
    public function setUnsafeInlineAllowed(string $directive = '', bool $allow = false): self
    {
        return $this->setAllowUnsafeInline($directive, $allow);
    }

    /**
     * Set strict-dynamic for a given directive.
     *
     * @param string $directive
     * @param bool $allow
     *
     * @return self
     * @throws Exception
     */
    public function setStrictDynamic(string $directive = '', bool $allow = false): self
    {
        $this->policies[$directive]['strict-dynamic'] = $allow;
        return $this;
    }

    /**
     * Set report-sample for a given directive.
     *
     * @param string $directive
     * @param bool $allow
     *
     * @return self
     * @throws Exception
     */
    public function setReportSample(string $directive = '', bool $allow = false): self
    {
        $this->policies[$directive]['report-sample'] = $allow;
        return $this;
    }

    /**
     * Set the Report URI to the desired string. This also sets the 'report-to'
     * component of the CSP header for CSP Level 3 compatibility.
     *
     * @param string $url
     * @return self
     */
    public function setReportUri(string $url = ''): self
    {
        $this->policies['report-uri'] = $url;
        return $this;
    }
    
    /**
     * Set the report-to directive to the desired string.
     *
     * @param string|array $policy
     * @return self
     */
    public function setReportTo($policy = ''): self
    {
        $this->policies['report-to'] = $policy;
        return $this;
    }

    /**
     * Compile a subgroup into a policy string
     *
     * @param string $directive
     * @param mixed $policies
     *
     * @return string
     */
    protected function compileSubgroup(string $directive, $policies = []): string
    {
        if ($policies === '*') {
            // Don't even waste the overhead adding this to the header
            return '';
        } elseif (empty($policies)) {
            if ($directive === 'plugin-types') {
                return '';
            } elseif ($directive === 'sandbox') {
                return $this->enc($directive) . '; ';
            }
            return $directive." 'none'; ";
        }
        /** @var array<array-key, mixed> $policies */

        $ret = $this->enc($directive) . ' ';
        if ($directive === 'plugin-types') {
            // Expects MIME types, not URLs
            $types = trim($this->enc(implode(' ', $policies['types']), 'mime'));
            return $types ? $ret . $types . '; ' : '';
        }
        if (!empty($policies['self'])) {
            $ret .= "'self' ";
        }

        if (!empty($policies['allow'])) {
            /** @var array<array-key, string> $allowedPolicies */
            $allowedPolicies = $policies['allow'];
            foreach (array_unique($allowedPolicies) as $url) {
                /** @var string|bool $url */
                $url = filter_var($url, FILTER_SANITIZE_URL);
                if (is_string($url)) {
                    if ($this->supportOldBrowsers && $directive !== 'sandbox') {
                        if (strpos($url, '://') === false) {
                            if (($this->isHTTPSConnection() && $this->httpsTransformOnHttpsConnections)
                                || !empty($this->policies['upgrade-insecure-requests'])) {
                                // We only want HTTPS connections here.
                                $ret .= 'https://'.$url.' ';
                            } else {
                                $ret .= 'https://'.$url.' http://'.$url.' ';
                            }
                        }
                    }
                    if (($this->isHTTPSConnection() && $this->httpsTransformOnHttpsConnections)
                        || !empty($this->policies['upgrade-insecure-requests'])) {
                        $ret .= str_replace('http://', 'https://', $url).' ';
                    } else {
                        $ret .= $url.' ';
                    }
                }
            }
        }

        if (!empty($policies['hashes'])) {
            /** @var array<array-key, array<string, string>> $hashes */
            $hashes = $policies['hashes'];
            foreach ($hashes as $hash) {
                /**
                 * @var string $algo
                 * @var string $hashval
                 */
                foreach ($hash as $algo => $hashval) {
                    $ret .= implode('', [
                        "'",
                        preg_replace('/[^A-Za-z0-9]/', '', $algo),
                        '-',
                        preg_replace('/[^A-Za-z0-9\+\/=]/', '', $hashval),
                        "' "
                    ]);
                }
            }
        }

        if (!empty($policies['nonces'])) {
            /** @var array<array-key, string> $nonces */
            $nonces = $policies['nonces'];
            foreach ($nonces as $nonce) {
                $ret .= implode('', [
                    "'nonce-",
                    preg_replace('/[^A-Za-z0-9\+\/=]/', '', $nonce),
                    "' "
                ]);
            }
        }

        if (!empty($policies['types'])) {
            /** @var array<array-key, string> $types */
            $types = $policies['types'];
            foreach ($types as $type) {
                $ret .= $type . ' ';
            }
        }

        if (!empty($policies['unsafe-hashes'])) {
            $ret .= "'unsafe-hashes' ";
        }
        if (!empty($policies['unsafe-inline'])) {
            $ret .= "'unsafe-inline' ";
        }
        if (!empty($policies['unsafe-eval'])) {
            $ret .= "'unsafe-eval' ";
        }
        if (!empty($policies['blob'])) {
            $ret .= "blob: ";
        }
        if (!empty($policies['data'])) {
            $ret .= "data: ";
        }
        if (!empty($policies['mediastream'])) {
            $ret .= "mediastream: ";
        }
        if (!empty($policies['filesystem'])) {
            $ret .= "filesystem: ";
        }
        if (!empty($policies['https'])) {
            $ret .= "https: ";
        }
        if (!empty($policies['strict-dynamic'])) {
            $ret .= "'strict-dynamic' ";
        }
        if (!empty($policies['report-sample'])) {
            $ret .= "'report-sample' ";
        }
        if (!empty($policies['unsafe-hashed-attributes'])) {
            $ret .= "'unsafe-hashed-attributes' ";
        }
        return rtrim($ret, ' ').'; ';
    }

    /**
     * Get an array of header keys to return
     *
     * @param bool $legacy
     * @return array
     */
    protected function getHeaderKeys(bool $legacy = true): array
    {
        // We always want this
        $return = [
            $this->reportOnly
                ? 'Content-Security-Policy-Report-Only'
                : 'Content-Security-Policy'
        ];

        // If we're supporting legacy devices, include these too:
        if ($legacy) {
            $return []= $this->reportOnly
                ? 'X-Content-Security-Policy-Report-Only'
                : 'X-Content-Security-Policy';
            $return []= $this->reportOnly
                ? 'X-Webkit-CSP-Report-Only'
                : 'X-Webkit-CSP';
        }
        return $return;
    }

    /**
     * @param string $piece
     * @param string $type
     * @return string
     */
    protected function enc(string $piece, string $type = 'default'): string
    {
        switch ($type) {
            case 'report-uri':
                return str_replace(["\r", "\n", ';'], '', $piece);
            case 'mime':
                if (preg_match('#^([a-z0-9\-/]+)#', $piece, $matches)) {
                    return $matches[1];
                }
                return '';
            case 'url':
                return urlencode($piece);
            default:
                // Don't inject
                return str_replace(
                    [';', "\r", "\n", ':'],
                    ['%3B', '%0D', '%0A', '%3A'],
                    $piece
                );
        }
    }

    /**
     * Is this user currently connected over HTTPS?
     *
     * @return bool
     * @psalm-suppress RiskyTruthyFalsyComparison
     */
    protected function isHTTPSConnection(): bool
    {
        if (!empty($_SERVER['HTTPS'])) {
            return $_SERVER['HTTPS'] !== 'off';
        }
        return false;
    }

    /**
     * Disable that HTTP sources get converted to HTTPS if the connection is such.
     *
     * @return self
     */
    public function disableHttpsTransformOnHttpsConnections(): self
    {
        $this->needsCompile = ($this->needsCompile || $this->httpsTransformOnHttpsConnections !== false);
        $this->httpsTransformOnHttpsConnections = false;

        return $this;
    }

    /**
     * Enable that HTTP sources get converted to HTTPS if the connection is such.
     *
     * This is enabled by default
     *
     * @return self
     */
    public function enableHttpsTransformOnHttpsConnections(): self
    {
        $this->needsCompile = ($this->needsCompile || $this->httpsTransformOnHttpsConnections !== true);
        $this->httpsTransformOnHttpsConnections = true;

        return $this;
    }

    /**
     * Export the policies object as a JSON string
     *
     * @return string
     */
    public function exportPolicies(): string
    {
        return json_encode($this->policies, JSON_PRETTY_PRINT);
    }

    /**
     * Save the configured policies to a JSON file.
     *
     * @param string $filePath
     * @return bool
     */
    public function saveToFile(string $filePath): bool
    {
        if (!is_writable($filePath)) {
            throw new RuntimeException('Cannot write to ' . $filePath);
        }
        return file_put_contents(
            $filePath,
            $this->exportPolicies()
        ) !== false;
    }
}
