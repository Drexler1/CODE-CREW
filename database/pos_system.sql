-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 19, 2026 at 04:15 PM
-- Server version: 10.4.32-MariaDB
-- PHP Version: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `pos_system`
--

-- --------------------------------------------------------

--
-- Table structure for table `admins`
--

CREATE TABLE `admins` (
  `admin_id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL DEFAULT '',
  `password` varchar(255) NOT NULL DEFAULT '',
  `full_name` varchar(255) NOT NULL DEFAULT '',
  `username_hash` varchar(64) DEFAULT NULL,
  `password_hash` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `admins`
--

INSERT INTO `admins` (`admin_id`, `username`, `password`, `full_name`, `username_hash`, `password_hash`) VALUES
(2, 'I5jNH60HBveDMRM2KhelUnr7wvhetRwuso2zL3ykki0=', 'jqWKe8PCQlZK/B6RAul/RzCLc3YmtXIbAzjAcci2Gpc=', 'NF9VHuSLUGk7dzDWCe/jO5M2A2kgmEcbQU+AP2fIfYA=', 'd3cf67bb19516daa1183e415e89271c7861396e4dbfdfda01cebc3b42674674a', '$2b$12$J19GG.l5tS/IjltwbTHIuO1pXQAFJFr0FPhkMCAPaPDcBDUvJJvIq');

-- --------------------------------------------------------

--
-- Table structure for table `app_settings`
--

CREATE TABLE `app_settings` (
  `setting_key` varchar(100) NOT NULL,
  `setting_value` varchar(500) NOT NULL DEFAULT '',
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `app_settings`
--

INSERT INTO `app_settings` (`setting_key`, `setting_value`, `updated_at`) VALUES
('late_grace_minutes', '10', '2026-05-19 13:49:20'),
('late_per_minute_rate', '0.7500', '2026-05-19 14:10:38');

-- --------------------------------------------------------

--
-- Table structure for table `attendance`
--

CREATE TABLE `attendance` (
  `attendance_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `shift_type` varchar(50) DEFAULT NULL,
  `clock_in` datetime DEFAULT NULL,
  `clock_out` datetime DEFAULT NULL,
  `attendance_date` date NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `hours_worked` decimal(10,4) NOT NULL DEFAULT 0.0000,
  `hourly_rate_snapshot` decimal(10,2) NOT NULL DEFAULT 0.00,
  `daily_earnings` decimal(10,2) NOT NULL DEFAULT 0.00,
  `pay_period_start` date DEFAULT NULL,
  `pay_period_end` date DEFAULT NULL,
  `daily_pay` decimal(10,2) DEFAULT NULL,
  `late_minutes` int(11) NOT NULL DEFAULT 0,
  `late_deduction` decimal(10,2) NOT NULL DEFAULT 0.00,
  `deduction_waived` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `attendance`
--

INSERT INTO `attendance` (`attendance_id`, `employee_id`, `shift_type`, `clock_in`, `clock_out`, `attendance_date`, `created_at`, `hours_worked`, `hourly_rate_snapshot`, `daily_earnings`, `pay_period_start`, `pay_period_end`, `daily_pay`, `late_minutes`, `late_deduction`, `deduction_waived`) VALUES
(7, 9, '8AM', '2026-05-19 22:12:42', NULL, '2026-05-19', '2026-05-19 14:12:42', 0.0000, 0.00, 0.00, NULL, NULL, NULL, 852, 639.00, 0);

-- --------------------------------------------------------

--
-- Table structure for table `categories`
--

CREATE TABLE `categories` (
  `category_id` int(10) UNSIGNED NOT NULL,
  `name` varchar(80) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `categories`
--

INSERT INTO `categories` (`category_id`, `name`, `created_at`) VALUES
(35, 'MILKTEA', '2026-04-05 16:23:19'),
(36, 'SNAKS', '2026-05-19 14:06:02');

-- --------------------------------------------------------

--
-- Table structure for table `email_alert_settings`
--

CREATE TABLE `email_alert_settings` (
  `id` int(11) NOT NULL,
  `smtp_host` varchar(255) NOT NULL DEFAULT '',
  `smtp_port` smallint(6) NOT NULL DEFAULT 587,
  `smtp_user` varchar(255) NOT NULL DEFAULT '',
  `smtp_password` varchar(255) NOT NULL DEFAULT '',
  `smtp_use_tls` tinyint(1) NOT NULL DEFAULT 1,
  `alert_recipient` varchar(255) NOT NULL DEFAULT '',
  `low_stock_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `low_stock_threshold` int(11) NOT NULL DEFAULT 5,
  `daily_summary_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `new_employee_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `failed_login_enabled` tinyint(1) NOT NULL DEFAULT 1,
  `maintenance_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `email_alert_settings`
--

INSERT INTO `email_alert_settings` (`id`, `smtp_host`, `smtp_port`, `smtp_user`, `smtp_password`, `smtp_use_tls`, `alert_recipient`, `low_stock_enabled`, `low_stock_threshold`, `daily_summary_enabled`, `new_employee_enabled`, `failed_login_enabled`, `maintenance_enabled`, `updated_at`) VALUES
(1, 'smtp.gmail.com', 587, 'patrimoniodrexler1@gmail.com', 'btvr qvkl xdpd wrtd', 1, 'patrimoniodrexler1@gmail.com', 1, 0, 1, 0, 1, 0, '2026-04-10 14:46:50');

-- --------------------------------------------------------

--
-- Table structure for table `employees`
--

CREATE TABLE `employees` (
  `employee_id` int(11) NOT NULL,
  `application_id` int(11) DEFAULT NULL,
  `full_name` varchar(255) NOT NULL DEFAULT '',
  `username` varchar(255) NOT NULL DEFAULT '',
  `password` varchar(255) NOT NULL DEFAULT '',
  `role` enum('admin','manager','cashier') NOT NULL DEFAULT 'cashier',
  `contact_number` varchar(255) NOT NULL DEFAULT '',
  `employment_status` enum('active','inactive','terminated') DEFAULT 'active',
  `face_image_path` varchar(255) DEFAULT NULL,
  `face_model_path` mediumtext DEFAULT NULL,
  `last_login` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `disabled_at` datetime DEFAULT NULL,
  `username_hash` varchar(64) DEFAULT NULL,
  `password_hash` varchar(255) DEFAULT NULL,
  `hourly_rate` decimal(10,2) NOT NULL DEFAULT 0.00
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `employees`
--

INSERT INTO `employees` (`employee_id`, `application_id`, `full_name`, `username`, `password`, `role`, `contact_number`, `employment_status`, `face_image_path`, `face_model_path`, `last_login`, `created_at`, `disabled_at`, `username_hash`, `password_hash`, `hourly_rate`) VALUES
(9, NULL, 'GXDKZNxunzPUkuaOlu0f2oIqaizoqrTJ/OUcMZVwsh0=', 'ndQlhzwM6Fd1857NFhRGfg7Padc/8Bcz9sOmQJdsJyg=', 'kZPVu4JuPfHqUZkqsYtVenkYyYddE2w8iprHQbHCPqc=', 'cashier', 'fpHa5IushQhAZ5c0MpfQxqx5vJuu6m9DVPuMVGcmVLA=', 'active', 'face_images/9.jpg', '{\"v\":1,\"emb\":[1.1382741034030914,0.4605010350545247,-0.08819212267796199,0.6577201187610626,0.8477630950510502,-0.34856319427490234,-0.24121978133916855,-0.5348358651002248,0.2590276598930359,-0.04825585832198461,0.6164255738258362,-0.10189367334047954,-0.14742360512415567,-0.7373632391293844,-0.2724164699514707,0.1710712512334188,1.4446428914864857,1.3766837418079376,-0.3924115610619386,0.534235214193662,-0.9398068388303121,0.18617237421373525,0.8319177428881327,-0.8732069532076517,-0.6368736575047175,-0.09628518670797348,0.23699518044789633,-0.8424260914325714,0.8579385181268057,0.06615490466356277,-0.11892118056615193,0.7147164146105448,-0.5203405767679214,0.3126053760449092,0.2680629715323448,-0.8734581420818964,-0.18602117399374643,-1.9930098354816437,-1.2091970145702362,0.8298642685015997,0.05117621769507726,-0.898281472424666,-0.07002503052353859,-0.09945545718073845,-0.8956413442889849,0.17861074457565942,-0.17122960090637207,1.1820462743441265,-0.9585422277450562,0.405602032939593,0.23889385908842087,-0.9239640434583029,0.27808333188295364,0.6036701798439026,0.43177420894304913,-0.7718892097473145,-0.36323437343041104,-0.1779778997103373,0.7092640499273936,0.34186268349488574,0.023360041280587513,1.1771377126375835,-0.026216318209966023,1.199468473593394,0.03608209267258644,-0.6162062187989553,-0.5138165950775146,-0.39298948148886365,0.3388683001200358,-0.45891529756287736,0.04331736514965693,0.5480534235636393,-0.32029207547505695,0.4182158410549164,0.12001190582911174,-1.0091214415927727,-0.437980055809021,-0.6535310397545496,0.5992112954457601,-0.15048951655626297,1.1341625650723774,-0.5302536487579346,-1.3806873460610707,0.2588455379009247,0.7698963632186254,0.061222389340400696,0.1576381971438726,0.39177586634953815,0.3896850248177846,-0.34273103314141434,0.6725977957248688,-0.2902212639649709,0.9916697641213735,-0.4973250925540924,0.22466213504473367,0.5075438345472018,-0.5224785891671976,1.39729310075442,-0.6633118987083435,0.7436946233113607,0.613144758467873,0.4451960225900014,-0.8871041238307953,0.9327675600846609,-0.024972716967264812,-0.2727370460828145,0.5805639376242956,-0.7435105443000793,0.24675452709197998,0.31589844822883606,1.1175222396850586,-0.5710375209649404,-0.44003884494304657,-0.38541972637176514,-0.9164141590396563,0.06035372614860535,0.19233979160586992,-0.5382285714149475,-0.5029015143712362,1.429765562216441,0.7914644082387289,0.42105700075626373,-0.9433664977550507,-0.7882126321395239,-0.5117257796227932,-0.8321234335501989,1.608357657988866,-1.5030324508746464,-0.31616532802581787,0.9483533700307211,-0.5653766418496767,-0.8154357572396597,-0.15851876636346182,-0.3887910743554433,-1.3285439411799114,0.4021979073683421,-1.182765652736028,-1.27617164204518,1.2501654922962189,1.2947450280189514,0.6744688302278519,0.5830569180349509,-0.6080246865749359,0.3977513909339905,0.4389617095390956,-0.6700415511926016,0.16143479943275452,0.10273276036605239,0.11904070650537808,-0.3705328206221263,1.3044662674268086,0.6878160536289215,-0.12143854548533757,1.1191847721735637,1.0428003668785095,-0.9979575624068578,-1.427764226992925,-0.2921952058871587,-0.5797029584646225,-0.668951744834582,0.7678878704706827,0.3684379458427429,-0.14048573871453604,0.9277443687121073,0.13693179935216904,0.2578110732138157,-0.30741334954897565,1.1294978360335033,-1.5542080501715343,-0.36975187063217163,-0.874917209148407,-0.22256875038146973,0.12420291701952617,0.5422609600548943,0.6213828027248383,1.1031013429164886,-0.6716515024503072,1.12206619232893,-0.1879201183716456,0.22384987771511078,-0.5517003436883291,-0.37069207429885864,-0.5065024197101593,-0.09214931726455688,1.0151018102963765,0.6120043098926544,0.5473413070042928,0.0013844867547353108,0.09987162177761395,1.2589322676261265,-0.10812323292096455,0.8282057841618856,1.0656517148017883,-1.4401928633451462,0.8501585721969604,-0.38008423646291095,-1.142172892888387,-0.21795586744944254,1.3046851605176926,-1.2265294392903645,1.028014858563741,-0.8950068056583405,0.6332160234451294,-0.46172020335992175,0.681143581867218,-0.6543890039126078,0.5745323995749155,0.8057276209195455,0.2657642401754856,1.3305612603823345,-1.1969155669212341,-0.22923975686232248,-0.02770094821850459,0.12736964225769043,-0.7040105958779653,0.4703084776798884,0.47025607774655026,0.5449596643447876,-1.1461150447527568,1.0719573150078456,-0.17150571445624033,-0.191325714190801,0.5318794548511505,0.4838819255431493,0.35670573140184086,0.32219187666972476,-0.4650156895319621,0.11782421792546909,-0.47020066281159717,0.05344642698764801,0.7708121140797933,-0.5282637278238932,-0.07297902554273605,-1.2760525743166606,-0.6749362349510193,-0.5908532813191414,-1.0149514923493068,1.0114845434824626,0.875978002945582,0.10344977428515752,0.38391465942064923,-0.7836861113707224,-0.2338989165922006,0.11773555725812912,0.6604063709576925,0.8457669317722321,-0.12325392050358157,-0.44899221261342365,0.6726790765921274,0.3823595444361369,-0.13558066387971243,0.15431836526840925,1.2258173922697704,-0.26142413914203644,-0.9689618448416392,-0.10399720445275307,-0.5107830762863159,0.6688566207885742,0.27072998881340027,0.5953904489676157,-1.0209110577901204,0.1531172494093577,0.8485360890626907,-1.0678239936629932,0.5418316125869751,-1.244496872027715,-0.11223090688387553,0.5871506184339523,-0.3097155864040057,-1.7463645736376445,1.1548775633176167,-0.05904688437779745,1.4526017506917317,-0.6499568819999695,-0.425890455643336,1.2427856015662353,0.027697645748655002,0.13306697209676108,0.4550138786435127,0.9073934902747472,0.04114760955174764,1.1843189001083374,-0.8833933075269064,0.24388758341471353,-0.5185075402259827,-0.8206900879740715,-0.5673651695251465,0.4334804018338521,0.13481863339742026,0.4106084903081258,-1.295823981364568,-0.7335648337999979,-0.2086231013139089,0.1348280981183052,0.8767384191354116,-0.21205246448516846,-0.44416263699531555,-0.747645099957784,-0.00025829098497827846,-0.8439913094043732,0.7857762177785238,-0.07915079904099305,-0.1497706895073255,0.23436558494965234,0.3650420010089874,0.016462579369544983,0.8184393843015035,-0.6087296704451243,-0.7754806876182556,-0.05081247538328171,-0.667847658197085,0.3245689521233241,0.1005545190225045,0.42460837463537854,1.4600891868273418,-0.28776733080546063,-0.6546970009803772,-0.017056524753570557,1.0055648982524872,-0.7032281706730524,0.8084436853726705,-0.38420231143633526,0.4214374323685964,1.4236107369263966,-0.5311274298777183,-0.313954030474027,-0.3115847110748291,1.6988967979947727,-0.522325336933136,0.08947762474417686,0.05160540590683619,0.7034088969230652,-0.3560637483994166,0.1374850794672966,0.28677891194820404,0.8532891869544983,0.8298632067938646,-0.654592752456665,-0.38466991980870563,0.4880441029866536,0.0884839619199435,-0.38953626714646816,-0.47410983840624493,-0.6648433804512024,0.9455865025520325,0.2482003594438235,-0.21047118057807288,0.45579079786936444,0.8082592189311981,0.27285243074099225,0.4709782948096593,-0.25793422261873883,-0.055343429247538246,0.17317438125610352,-0.917862594127655,0.28614984452724457,0.7922928134600321,0.1304717759291331,0.6498595575491587,0.17464395239949226,-0.39576370020707446,-0.6689285337924957,-0.741956869761149,-0.33169950544834137,0.06678354491790135,0.7913869420687357,-0.4769062002499898,-0.3019532635807991,-0.6670788327852885,0.1756238117814064,-1.0736084679762523,-1.0693958501021068,-1.0328454871972401,0.8023456980784734,0.5216356416543325,1.8113216658433278,-0.6484220921993256,1.028728038072586,-0.4314902325471242,0.8450441857179006,-0.5371955633163452,-0.03161381185054779,-1.2132067581017811,0.9156767974297205,0.8747898402313391,-0.350444495677948,-0.7718617220719656,1.4765719970067341,0.04599460711081823,0.10099457701047261,-0.059545074899991356,0.42155681053797406,-1.1787670453389485,0.856587549050649,-0.36482612291971844,-0.5729353527228037,-0.10189860065778096,0.638048325975736,0.08219171067078908,-1.4994230270385742,-0.4039434889952342,-0.07106635967890422,0.23231752961874008,0.8278548121452332,0.4860941246151924,-0.8918134768803915,-1.1568424453337987,-0.62313312292099,0.6135664582252502,-0.18303375070293745,1.4255847930908203,0.1262715458869934,0.26798345645268756,-0.41810449957847595,-0.2822177509466807,-0.5851963957150778,0.8597849408785502,1.524275968472163,0.020204047362009685,-0.2382715940475464,-0.17173095544179282,-0.1847795695066452,-0.614399254322052,0.7673551837603251,0.18333144982655844,0.8967157105604807,0.42965524395306903,-0.3848882516225179,0.01992078311741352,-0.15710378686587015,-0.9678223306934038,0.6784992516040802,-0.0295512309918801,-0.8306544125080109,0.07332047820091248,0.6670039842526118,-0.8534363309542338,-1.3557494978109996,-0.689064602057139,0.5460919141769409,-0.5611362953980764,0.20241746803124747,-0.6682096918423971,0.5704478025436401,-0.7338949913779894,0.003179877996444702,0.011353886996706327,0.21567636355757713,-0.6035360296567281,-0.900581161181132,-0.16379216313362122,-0.6162806650002798,0.5766648054122925,-0.28939791520436603,-0.06731365621089935,0.04091831420858701,-0.904024749994278,0.23690951988101006,0.2819567422072093,1.0167914132277172,0.3580577572186788,1.1783905923366547,0.37933581198255223,0.8770579745372137,-0.19260134299596152,0.10626238584518433,1.2199832995732625,-1.709740974009037,0.9067753354708353,0.46179285645484924,1.1389995614687602,-0.36011911928653717,0.2562292714913686,-0.25379719336827594,-0.9575116833051046,0.3399239182472229,0.7524839043617249,-0.1975176235040029,0.09239554405212402,0.561176578203837,0.6193026701609293,0.3598770002524058,0.37282875676949817,0.7644760807355245,-0.3815782368183136,-0.3680250446001689,-1.0218866070111592,1.4274650017420452,0.33526373902956647,-1.2240435530742009,-0.3764668603738149,-1.3518271694580715,-0.6442720393339793,-0.4358235001564026,0.7336847186088562,-1.1298810243606567,-0.46792636315027875,0.5400837858517965,0.14955483873685202,-0.5116739099224409,-0.3700130184491475,-0.649634396036466,-0.41252685338258743,-0.4114705075820287,-0.530847375591596,0.8329960107803345,-0.33108679577708244,0.2365737408399582,-0.09683601309855779,-1.8853353566179674,0.5232962970621884,0.025740305582682293]}', '2026-05-19 21:55:12', '2026-05-19 13:53:19', NULL, 'cd38b9cf0947f8f1f7f1e18ff732168b28b7be0e7d016f75e6974893996720d2', '$2b$12$AUSrnRNlHqTQX8AZXQJLIe5pq24dpgz0/qlASNd5kUWBH2PQJqu5e', 45.00);

-- --------------------------------------------------------

--
-- Table structure for table `employees_trash`
--

CREATE TABLE `employees_trash` (
  `trash_id` int(10) UNSIGNED NOT NULL,
  `employee_id` int(11) NOT NULL,
  `full_name` varchar(255) NOT NULL DEFAULT '',
  `username` varchar(255) NOT NULL DEFAULT '',
  `username_hash` varchar(64) DEFAULT NULL,
  `password` varchar(255) NOT NULL DEFAULT '',
  `password_hash` varchar(255) DEFAULT NULL,
  `role` enum('admin','manager','cashier') NOT NULL DEFAULT 'cashier',
  `contact_number` varchar(255) NOT NULL DEFAULT '',
  `face_image_path` varchar(255) DEFAULT NULL,
  `face_model_path` mediumtext DEFAULT NULL,
  `last_login` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `disabled_at` datetime NOT NULL DEFAULT current_timestamp(),
  `delete_at` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `employee_applications`
--

CREATE TABLE `employee_applications` (
  `application_id` int(11) NOT NULL,
  `full_name` varchar(255) NOT NULL DEFAULT '',
  `email` varchar(255) NOT NULL DEFAULT '',
  `username` varchar(255) NOT NULL DEFAULT '',
  `role` enum('admin','manager','cashier') NOT NULL DEFAULT 'cashier',
  `contact_number` varchar(255) NOT NULL DEFAULT '',
  `status` enum('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `face_mismatch_log`
--

CREATE TABLE `face_mismatch_log` (
  `id` int(10) UNSIGNED NOT NULL,
  `employee_id` int(11) NOT NULL,
  `attempted_at` datetime NOT NULL DEFAULT current_timestamp(),
  `distance_score` float DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `user_agent` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `face_mismatch_log`
--

INSERT INTO `face_mismatch_log` (`id`, `employee_id`, `attempted_at`, `distance_score`, `ip_address`, `user_agent`) VALUES
(1, 1, '2026-03-25 08:55:09', 0.6711, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(2, 1, '2026-03-25 08:55:32', 0.6885, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(3, 1, '2026-03-25 08:55:45', 0.7331, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(4, 1, '2026-03-25 12:33:22', 0.3156, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(5, 1, '2026-03-25 12:33:28', 0.8002, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(6, 1, '2026-03-25 12:33:43', 0.4578, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(7, 1, '2026-03-25 12:33:53', 0.4503, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(8, 1, '2026-03-25 12:33:58', 0.301, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(9, 1, '2026-03-25 12:34:04', 0.3761, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(10, 1, '2026-03-25 12:35:08', 0.4677, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(11, 2, '2026-03-25 12:36:56', 0.3106, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(12, 2, '2026-03-25 12:37:13', 0.367, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(13, 2, '2026-03-25 12:38:00', 0.4079, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(14, 2, '2026-03-25 12:38:14', 0.6877, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(15, 2, '2026-03-25 12:39:01', 0.3209, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(16, 2, '2026-03-25 12:39:20', 0.3051, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(17, 2, '2026-03-25 12:39:39', 0.7074, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(18, 2, '2026-03-25 12:42:29', 0.6511, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(19, 2, '2026-03-25 12:42:33', 0.6217, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(20, 2, '2026-03-25 12:42:35', 0.6179, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(21, 2, '2026-03-25 13:23:52', 0.6914, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(22, 2, '2026-03-25 13:24:06', 0.6406, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(23, 2, '2026-03-25 14:28:32', 0.662, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(24, 2, '2026-03-25 14:30:42', 0.6833, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(25, 2, '2026-03-25 15:00:52', 0.4435, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(26, 3, '2026-03-25 15:00:56', 0.5634, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(27, 3, '2026-03-25 15:01:08', 0.4741, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(28, 2, '2026-03-25 15:01:09', 0.4562, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(29, 3, '2026-03-25 15:01:19', 0.4432, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(30, 2, '2026-03-25 15:01:32', 0.4416, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(31, 3, '2026-03-25 15:19:36', 0.5779, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(32, 3, '2026-03-25 15:48:58', 0.6949, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36'),
(33, 3, '2026-03-25 16:27:39', 0.517, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(34, 5, '2026-03-26 07:41:25', 0.3381, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(35, 5, '2026-03-26 07:41:42', 0.6013, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(36, 5, '2026-03-26 07:45:05', 0.4796, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(37, 5, '2026-03-26 07:46:25', 0.8069, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(38, 3, '2026-03-27 00:14:49', 0.5249, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(39, 3, '2026-03-27 00:29:10', 0.5543, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(40, 3, '2026-03-27 00:29:46', 0.58, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(41, 3, '2026-03-27 00:30:47', 0.6344, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(42, 5, '2026-03-27 07:54:34', 0.5163, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0'),
(43, 3, '2026-03-31 23:38:48', 0.5825, '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0');

-- --------------------------------------------------------

--
-- Table structure for table `inv_items`
--

CREATE TABLE `inv_items` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(120) NOT NULL,
  `type` enum('ingredient','packaging') NOT NULL DEFAULT 'ingredient',
  `stock` decimal(12,2) NOT NULL DEFAULT 0.00,
  `unit` varchar(20) NOT NULL DEFAULT 'pcs',
  `reorder_point` decimal(12,2) NOT NULL DEFAULT 10.00,
  `note` varchar(255) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `inv_items`
--

INSERT INTO `inv_items` (`id`, `name`, `type`, `stock`, `unit`, `reorder_point`, `note`, `is_active`, `created_at`, `updated_at`) VALUES
(4, '8oz Cup', 'packaging', 21.00, '8oz', 20.00, 'Cup packaging — auto-deducted on sales', 1, '2026-04-05 16:03:13', '2026-04-10 15:01:36'),
(5, '12oz Cup', 'packaging', 5.00, '12oz', 20.00, 'Cup packaging — auto-deducted on sales', 1, '2026-04-05 16:03:21', '2026-04-05 16:03:27'),
(6, '16oz Cup', 'packaging', 5.00, '16oz', 20.00, 'Cup packaging — auto-deducted on sales', 1, '2026-04-05 16:03:28', '2026-04-05 16:03:32'),
(7, 'Sugar', 'ingredient', 2.00, 'kg', 10.00, NULL, 1, '2026-04-10 15:02:25', '2026-04-10 15:18:50'),
(8, 'Brown Syrup', 'packaging', 1.00, 'bottle', 10.00, NULL, 1, '2026-04-24 14:47:59', '2026-04-24 14:47:59');

-- --------------------------------------------------------

--
-- Table structure for table `inv_log`
--

CREATE TABLE `inv_log` (
  `log_id` int(10) UNSIGNED NOT NULL,
  `item_id` int(10) UNSIGNED NOT NULL,
  `item_name` varchar(120) NOT NULL DEFAULT '',
  `unit` varchar(20) NOT NULL DEFAULT 'pcs',
  `delta` decimal(12,2) NOT NULL,
  `stock_after` decimal(12,2) NOT NULL,
  `source` enum('sale','manual') NOT NULL DEFAULT 'manual',
  `transaction_id` int(10) UNSIGNED DEFAULT NULL,
  `note` varchar(255) DEFAULT NULL,
  `created_by` varchar(80) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `inv_log`
--

INSERT INTO `inv_log` (`log_id`, `item_id`, `item_name`, `unit`, `delta`, `stock_after`, `source`, `transaction_id`, `note`, `created_by`, `created_at`) VALUES
(11, 4, '8oz Cup', '8oz', 1.00, 6.00, 'manual', NULL, NULL, 'Drexler', '2026-04-05 16:23:06'),
(12, 4, '8oz Cup', '8oz', -1.00, 5.00, 'sale', 18, 'Auto-deducted via TXN #18', 'Patrimonio', '2026-04-05 17:03:27'),
(13, 4, '8oz Cup', '8oz', -1.00, 4.00, 'sale', 19, 'Auto-deducted via TXN #19', 'Patrimonio', '2026-04-05 17:07:59'),
(14, 4, '8oz Cup', '8oz', -1.00, 3.00, 'sale', 20, 'Auto-deducted via TXN #20', 'Patrimonio', '2026-04-05 17:13:34'),
(15, 4, '8oz Cup', '8oz', -1.00, 2.00, 'sale', 21, 'Auto-deducted via TXN #21', 'Patrimonio', '2026-04-09 13:18:26'),
(16, 4, '8oz Cup', '8oz', -1.00, 1.00, 'sale', 22, 'Auto-deducted via TXN #22', 'Patrimonio', '2026-04-10 13:32:09'),
(17, 4, '8oz Cup', '8oz', 5.00, 6.00, 'manual', NULL, NULL, 'Drexler', '2026-04-10 15:01:24'),
(18, 4, '8oz Cup', '8oz', 5.00, 11.00, 'manual', NULL, NULL, 'Drexler', '2026-04-10 15:01:29'),
(19, 4, '8oz Cup', '8oz', 10.00, 21.00, 'manual', NULL, NULL, 'Drexler', '2026-04-10 15:01:36'),
(20, 7, 'Sugar', 'kg', 1.00, 2.00, 'manual', NULL, NULL, 'Drexler', '2026-04-10 15:18:50');

-- --------------------------------------------------------

--
-- Table structure for table `login_attempts`
--

CREATE TABLE `login_attempts` (
  `attempt_key` varchar(64) NOT NULL,
  `fail_count` int(11) NOT NULL DEFAULT 0,
  `locked_until` datetime DEFAULT NULL,
  `last_attempt` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `login_attempts`
--

INSERT INTO `login_attempts` (`attempt_key`, `fail_count`, `locked_until`, `last_attempt`) VALUES
('0f50b0d848d29f2476624f171dc2d442266e35bed28ad11e830d6cf09f2b0929', 3, NULL, '2026-04-04 14:34:07'),
('3049ea9e4b0a7b1b19db0afff84bc4434878d00c503dc9b9fa6a8a257c4f67e6', 4, NULL, '2026-03-26 11:36:53'),
('85d636564759f084aae5de99f84bf6246f97cfea6c02769f55484c7eba9bec4d', 5, '2026-04-05 17:42:20', '2026-04-05 17:27:20'),
('a49a0bc44eb86fb946e61a404978255950b48af6daaaec520e2a6fdd8120104c', 1, NULL, '2026-04-24 15:00:51');

-- --------------------------------------------------------

--
-- Table structure for table `overtime_requests`
--

CREATE TABLE `overtime_requests` (
  `request_id` int(11) NOT NULL,
  `employee_id` int(11) NOT NULL,
  `attendance_id` int(11) DEFAULT NULL,
  `request_date` date NOT NULL,
  `extended_hours` decimal(4,2) NOT NULL,
  `reason` varchar(500) NOT NULL DEFAULT '',
  `status` enum('pending','approved','denied','cancelled') NOT NULL DEFAULT 'pending',
  `reviewed_by` varchar(255) DEFAULT NULL,
  `reviewed_at` datetime DEFAULT NULL,
  `admin_note` varchar(500) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `payroll_periods`
--

CREATE TABLE `payroll_periods` (
  `payroll_id` int(10) UNSIGNED NOT NULL,
  `employee_id` int(11) NOT NULL,
  `period_start` date NOT NULL,
  `period_end` date NOT NULL,
  `total_hours` decimal(8,2) NOT NULL DEFAULT 0.00,
  `total_pay` decimal(12,2) NOT NULL DEFAULT 0.00,
  `days_worked` smallint(6) NOT NULL DEFAULT 0,
  `status` enum('draft','finalized') NOT NULL DEFAULT 'draft',
  `generated_at` datetime NOT NULL DEFAULT current_timestamp(),
  `finalized_at` datetime DEFAULT NULL,
  `notes` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `products`
--

CREATE TABLE `products` (
  `product_id` int(10) UNSIGNED NOT NULL,
  `category_id` int(10) UNSIGNED DEFAULT NULL,
  `name` varchar(120) NOT NULL,
  `description` text DEFAULT NULL,
  `sku` varchar(60) DEFAULT NULL,
  `price` decimal(10,2) NOT NULL DEFAULT 0.00,
  `cost` decimal(10,2) NOT NULL DEFAULT 0.00,
  `stock` int(11) NOT NULL DEFAULT 0,
  `reorder_point` int(11) NOT NULL DEFAULT 5,
  `unit` varchar(30) NOT NULL DEFAULT 'pcs',
  `icon` varchar(10) NOT NULL DEFAULT '?',
  `image_url` varchar(512) DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `cup_eligible` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `products`
--

INSERT INTO `products` (`product_id`, `category_id`, `name`, `description`, `sku`, `price`, `cost`, `stock`, `reorder_point`, `unit`, `icon`, `image_url`, `is_active`, `created_at`, `updated_at`, `cup_eligible`) VALUES
(31, 35, 'Spanish Latte', NULL, 'MT-001', 140.00, 50.00, -7, 5, 'pcs', '📦', '/static/product_images/prod_d9f2c031002e661d58c969ff.jpg', 1, '2026-04-05 16:23:44', '2026-04-13 13:16:38', 1),
(32, 36, 'Cheepy', NULL, NULL, 30.00, 10.00, 0, 5, 'pcs', '?', NULL, 1, '2026-05-19 14:06:24', '2026-05-19 14:06:24', 0);

-- --------------------------------------------------------

--
-- Table structure for table `shift_config`
--

CREATE TABLE `shift_config` (
  `id` int(11) NOT NULL,
  `label` varchar(100) NOT NULL,
  `start_time` varchar(5) NOT NULL,
  `end_time` varchar(5) NOT NULL,
  `color` varchar(20) NOT NULL DEFAULT '#c9a961',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `shift_config`
--

INSERT INTO `shift_config` (`id`, `label`, `start_time`, `end_time`, `color`, `created_at`) VALUES
(1, '8AM', '08:00', '18:00', '#4caf50', '2026-05-19 14:12:12');

-- --------------------------------------------------------

--
-- Table structure for table `stock_requests`
--

CREATE TABLE `stock_requests` (
  `id` int(10) UNSIGNED NOT NULL,
  `item_name` varchar(120) NOT NULL,
  `item_type` enum('ingredient','packaging') NOT NULL DEFAULT 'ingredient',
  `quantity` decimal(12,2) NOT NULL DEFAULT 0.00,
  `unit` varchar(20) NOT NULL DEFAULT 'pcs',
  `note` varchar(255) DEFAULT NULL,
  `requested_by` varchar(80) NOT NULL,
  `requested_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `status` enum('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  `reviewed_by` varchar(80) DEFAULT NULL,
  `reviewed_at` timestamp NULL DEFAULT NULL,
  `review_note` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `transactions`
--

CREATE TABLE `transactions` (
  `transaction_id` int(10) UNSIGNED NOT NULL,
  `cashier_id` int(11) NOT NULL,
  `cashier_name` varchar(255) NOT NULL DEFAULT '',
  `subtotal` decimal(12,2) NOT NULL DEFAULT 0.00,
  `discount_amount` decimal(12,2) NOT NULL DEFAULT 0.00,
  `tax_amount` decimal(12,2) NOT NULL DEFAULT 0.00,
  `total_amount` decimal(12,2) NOT NULL DEFAULT 0.00,
  `amount_tendered` decimal(12,2) NOT NULL DEFAULT 0.00,
  `change_amount` decimal(12,2) NOT NULL DEFAULT 0.00,
  `payment_method` enum('cash','card','gcash','maya','other') NOT NULL DEFAULT 'cash',
  `note` varchar(255) DEFAULT NULL,
  `status` enum('completed','voided') NOT NULL DEFAULT 'completed',
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `discount_type` enum('none','senior','pwd','manual') NOT NULL DEFAULT 'none',
  `net_sales` decimal(12,2) NOT NULL DEFAULT 0.00,
  `vat_amount` decimal(12,2) NOT NULL DEFAULT 0.00
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `transaction_items`
--

CREATE TABLE `transaction_items` (
  `item_id` int(10) UNSIGNED NOT NULL,
  `transaction_id` int(10) UNSIGNED NOT NULL,
  `product_id` int(10) UNSIGNED DEFAULT NULL,
  `product_name` varchar(120) NOT NULL,
  `category_name` varchar(80) NOT NULL DEFAULT '',
  `unit_price` decimal(10,2) NOT NULL DEFAULT 0.00,
  `quantity` int(11) NOT NULL DEFAULT 1,
  `line_total` decimal(12,2) NOT NULL DEFAULT 0.00
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `admins`
--
ALTER TABLE `admins`
  ADD PRIMARY KEY (`admin_id`);

--
-- Indexes for table `app_settings`
--
ALTER TABLE `app_settings`
  ADD PRIMARY KEY (`setting_key`);

--
-- Indexes for table `attendance`
--
ALTER TABLE `attendance`
  ADD PRIMARY KEY (`attendance_id`),
  ADD KEY `attendance_ibfk_1` (`employee_id`);

--
-- Indexes for table `categories`
--
ALTER TABLE `categories`
  ADD PRIMARY KEY (`category_id`),
  ADD UNIQUE KEY `uq_category_name` (`name`);

--
-- Indexes for table `email_alert_settings`
--
ALTER TABLE `email_alert_settings`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `employees`
--
ALTER TABLE `employees`
  ADD PRIMARY KEY (`employee_id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD KEY `application_id` (`application_id`);

--
-- Indexes for table `employees_trash`
--
ALTER TABLE `employees_trash`
  ADD PRIMARY KEY (`trash_id`),
  ADD KEY `idx_delete_at` (`delete_at`),
  ADD KEY `idx_employee_id` (`employee_id`);

--
-- Indexes for table `employee_applications`
--
ALTER TABLE `employee_applications`
  ADD PRIMARY KEY (`application_id`),
  ADD UNIQUE KEY `email` (`email`),
  ADD UNIQUE KEY `username` (`username`);

--
-- Indexes for table `face_mismatch_log`
--
ALTER TABLE `face_mismatch_log`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_employee_id` (`employee_id`),
  ADD KEY `idx_attempted_at` (`attempted_at`);

--
-- Indexes for table `inv_items`
--
ALTER TABLE `inv_items`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_type` (`type`),
  ADD KEY `idx_active` (`is_active`);

--
-- Indexes for table `inv_log`
--
ALTER TABLE `inv_log`
  ADD PRIMARY KEY (`log_id`),
  ADD KEY `idx_item` (`item_id`),
  ADD KEY `idx_created_at` (`created_at`),
  ADD KEY `idx_source` (`source`);

--
-- Indexes for table `login_attempts`
--
ALTER TABLE `login_attempts`
  ADD PRIMARY KEY (`attempt_key`);

--
-- Indexes for table `overtime_requests`
--
ALTER TABLE `overtime_requests`
  ADD PRIMARY KEY (`request_id`),
  ADD KEY `idx_ot_employee` (`employee_id`),
  ADD KEY `idx_ot_status` (`status`),
  ADD KEY `idx_ot_date` (`request_date`);

--
-- Indexes for table `payroll_periods`
--
ALTER TABLE `payroll_periods`
  ADD PRIMARY KEY (`payroll_id`),
  ADD UNIQUE KEY `uq_emp_period` (`employee_id`,`period_start`),
  ADD KEY `idx_period_start` (`period_start`),
  ADD KEY `idx_employee_id` (`employee_id`);

--
-- Indexes for table `products`
--
ALTER TABLE `products`
  ADD PRIMARY KEY (`product_id`),
  ADD KEY `idx_category` (`category_id`),
  ADD KEY `idx_active` (`is_active`);

--
-- Indexes for table `shift_config`
--
ALTER TABLE `shift_config`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `stock_requests`
--
ALTER TABLE `stock_requests`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `transactions`
--
ALTER TABLE `transactions`
  ADD PRIMARY KEY (`transaction_id`),
  ADD KEY `idx_cashier` (`cashier_id`),
  ADD KEY `idx_created_at` (`created_at`),
  ADD KEY `idx_status` (`status`);

--
-- Indexes for table `transaction_items`
--
ALTER TABLE `transaction_items`
  ADD PRIMARY KEY (`item_id`),
  ADD KEY `idx_tx` (`transaction_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `admins`
--
ALTER TABLE `admins`
  MODIFY `admin_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `attendance`
--
ALTER TABLE `attendance`
  MODIFY `attendance_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=8;

--
-- AUTO_INCREMENT for table `categories`
--
ALTER TABLE `categories`
  MODIFY `category_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=37;

--
-- AUTO_INCREMENT for table `email_alert_settings`
--
ALTER TABLE `email_alert_settings`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `employees`
--
ALTER TABLE `employees`
  MODIFY `employee_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- AUTO_INCREMENT for table `employees_trash`
--
ALTER TABLE `employees_trash`
  MODIFY `trash_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `employee_applications`
--
ALTER TABLE `employee_applications`
  MODIFY `application_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `face_mismatch_log`
--
ALTER TABLE `face_mismatch_log`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=44;

--
-- AUTO_INCREMENT for table `inv_items`
--
ALTER TABLE `inv_items`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT for table `inv_log`
--
ALTER TABLE `inv_log`
  MODIFY `log_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=21;

--
-- AUTO_INCREMENT for table `overtime_requests`
--
ALTER TABLE `overtime_requests`
  MODIFY `request_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `payroll_periods`
--
ALTER TABLE `payroll_periods`
  MODIFY `payroll_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT for table `products`
--
ALTER TABLE `products`
  MODIFY `product_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=33;

--
-- AUTO_INCREMENT for table `shift_config`
--
ALTER TABLE `shift_config`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `stock_requests`
--
ALTER TABLE `stock_requests`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `transactions`
--
ALTER TABLE `transactions`
  MODIFY `transaction_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=24;

--
-- AUTO_INCREMENT for table `transaction_items`
--
ALTER TABLE `transaction_items`
  MODIFY `item_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=24;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `attendance`
--
ALTER TABLE `attendance`
  ADD CONSTRAINT `attendance_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `employees` (`employee_id`) ON DELETE CASCADE;

--
-- Constraints for table `employees`
--
ALTER TABLE `employees`
  ADD CONSTRAINT `employees_ibfk_1` FOREIGN KEY (`application_id`) REFERENCES `employee_applications` (`application_id`) ON DELETE SET NULL;

--
-- Constraints for table `payroll_periods`
--
ALTER TABLE `payroll_periods`
  ADD CONSTRAINT `payroll_periods_ibfk_1` FOREIGN KEY (`employee_id`) REFERENCES `employees` (`employee_id`) ON DELETE CASCADE;

--
-- Constraints for table `products`
--
ALTER TABLE `products`
  ADD CONSTRAINT `fk_product_category` FOREIGN KEY (`category_id`) REFERENCES `categories` (`category_id`) ON DELETE SET NULL;

--
-- Constraints for table `transaction_items`
--
ALTER TABLE `transaction_items`
  ADD CONSTRAINT `fk_ti_transaction` FOREIGN KEY (`transaction_id`) REFERENCES `transactions` (`transaction_id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
